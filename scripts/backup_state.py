"""Offline IAM state backups. Archives contain credentials and are NOT encrypted."""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"iam.sqlite3", "oidc-signing-key.pem", "factor-encryption.key"}
ALLOWED = REQUIRED | {"deployment.json"}
LIMITS = {"iam.sqlite3": 2 * 1024**3, "oidc-signing-key.pem": 65536,
          "factor-encryption.key": 1024, "deployment.json": 1024**2, "manifest.json": 65536}
REQUIRED_TABLES = {"users", "resources", "sessions", "audit", "oauth_apps", "totp_factors", "passkeys"}


class BackupError(ValueError):
    """Safe operator-facing error, without secret-bearing input values."""


def _path(value: Path) -> Path:
    """Reject symbolic links and Windows junction/reparse points, including parents."""
    path = Path(os.path.abspath(value))
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BackupError("Symbolic links and reparse points are not supported.")
    return path


def _regular(path: Path) -> Path:
    path = _path(path)
    if not path.is_file():
        raise BackupError("A required regular file is missing.")
    return path


def _supported_platform() -> None:
    if os.name != "nt" and sys.platform != "linux":
        raise BackupError("Private backup/restore is supported only on Windows and Linux.")


def _windows_create_private(path: Path, *, directory=False) -> int | None:
    """Supply a protected owner/SYSTEM DACL to Windows at object creation."""
    from ctypes import wintypes
    import msvcrt

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                    ("inherit_handle", wintypes.BOOL)]

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                                          ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD,
                                 wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE

    # FAT and other filesystems without persistent ACLs cannot protect credentials.
    volume = ctypes.create_unicode_buffer(32768)
    flags = wintypes.DWORD()
    if not kernel.GetVolumePathNameW(str(path.parent), volume, len(volume)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel.GetVolumeInformationW(volume.value, None, 0, None, None, ctypes.byref(flags), None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    if not flags.value & 0x8:  # FILE_PERSISTENT_ACLS
        raise BackupError("The Windows filesystem must support persistent access-control lists.")

    token = wintypes.HANDLE()
    owner = wintypes.LPWSTR()
    descriptor = ctypes.c_void_p()
    try:
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):  # TOKEN_QUERY
            raise ctypes.WinError(ctypes.get_last_error())
        needed = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
        if not needed.value:
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(token, 1, user, len(user), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(user, ctypes.POINTER(SidAndAttributes)).contents.sid
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(owner)):
            raise ctypes.WinError(ctypes.get_last_error())
        inheritance = "OICI" if directory else ""
        dacl = f"O:{owner.value}D:P(A;{inheritance};FA;;;{owner.value})(A;{inheritance};FA;;;SY)"
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if directory:
            if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                raise ctypes.WinError(ctypes.get_last_error())
            return None
        # CREATE_NEW refuses an existing file. No inherited ACL or writable
        # secret-bearing file exists before the protected DACL takes effect.
        handle = kernel.CreateFileW(str(path), 0xC0000000, 0, ctypes.byref(attributes), 1, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(handle)
            raise
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if owner:
            kernel.LocalFree(ctypes.cast(owner, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def _private_file(path: Path):
    _supported_platform()
    descriptor = (_windows_create_private(path) if os.name == "nt" else
                  os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    try:
        return os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _private_stage(parent: Path, prefix: str):
    _supported_platform()
    if os.name == "nt":
        for _ in range(100):
            stage = parent / (prefix + secrets.token_hex(16))
            try:
                _windows_create_private(stage, directory=True)
                break
            except FileExistsError:
                continue
        else:
            raise BackupError("Could not reserve a new private staging directory.")
    else:
        stage = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))  # mode 0700 at creation
    identity = stage.stat()
    # The restore caller marks publication by removing this path from cleanup.
    owned = {"path": stage}
    try:
        yield owned
    finally:
        if owned["path"] is not None:
            try:
                current = stage.lstat()
            except FileNotFoundError:
                pass
            else:
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    shutil.rmtree(stage)


def _publish_directory(stage: Path, target: Path) -> None:
    if os.name == "nt":
        # Unlike POSIX rename(), Windows refuses even an empty existing target.
        os.rename(stage, target)
    elif sys.platform == "linux":
        try:
            rename = ctypes.CDLL(None, use_errno=True).renameat2
        except (AttributeError, OSError) as exc:
            raise BackupError("Atomic no-replace restore requires Linux renameat2 support.") from exc
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        # RENAME_NOREPLACE is one atomic kernel operation, including collision detection.
        if rename(-100, os.fsencode(stage), -100, os.fsencode(target), 1):
            code = ctypes.get_errno()
            if code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
                raise BackupError("Atomic no-replace restore is unsupported by this Linux kernel/filesystem.")
            raise OSError(code or errno.EIO, os.strerror(code or errno.EIO), str(target))
    else:
        _supported_platform()


def _private_copy(source: Path, target: Path, limit: int) -> None:
    _regular(source)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as incoming:
        info = os.fstat(incoming.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise BackupError("A state file has an unsupported type or size.")
        with _private_file(target) as outgoing:
            remaining = info.st_size
            while chunk := incoming.read(min(1024 * 1024, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise BackupError("State changed during backup; stop all writers and retry.")
                outgoing.write(chunk)
        if target.stat().st_size != info.st_size:
            raise BackupError("State changed during backup; stop all writers and retry.")


def _connect(path: Path, *, immutable=False):
    # Staged snapshots are standalone files. Immutable reads cannot create sidecars.
    suffix = "?mode=ro&immutable=1" if immutable else "?mode=ro"
    db = sqlite3.connect(path.as_uri() + suffix, uri=True, timeout=5)
    db.execute("PRAGMA trusted_schema=OFF")
    db.execute("PRAGMA query_only=ON")
    return db


def _database_metadata(path: Path) -> dict:
    with closing(_connect(path, immutable=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise BackupError("SQLite integrity validation failed.")
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise BackupError("SQLite foreign-key validation failed.")
        tables = sorted(row[0] for row in db.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
        if not REQUIRED_TABLES <= set(tables):
            raise BackupError("SQLite state lacks required IAM identity tables.")
        return {"user_version": db.execute("PRAGMA user_version").fetchone()[0],
                "application_id": db.execute("PRAGMA application_id").fetchone()[0], "tables": tables}


def _json(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BackupError("Duplicate JSON fields are not supported.")
            result[key] = value
        return result
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique)


def _validate_state(directory: Path) -> dict:
    # Use the backend's installed cryptography dependency; never emit key bytes.
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    metadata = _database_metadata(directory / "iam.sqlite3")
    try:
        key = serialization.load_pem_private_key((directory / "oidc-signing-key.pem").read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError
        cipher = Fernet((directory / "factor-encryption.key").read_bytes())
        with closing(_connect(directory / "iam.sqlite3", immutable=True)) as db:
            for table in ("totp_factors", "factor_enrollments"):
                if table in metadata["tables"]:
                    for row in db.execute(f"SELECT encrypted_secret FROM {table}"):
                        cipher.decrypt(row[0].encode())
        deployment = directory / "deployment.json"
        if deployment.exists() and not isinstance(_json(deployment.read_bytes()), dict):
            raise ValueError
    except Exception as exc:
        raise BackupError("Signing key, factor key or deployment metadata validation failed.") from exc
    return metadata


def _digest(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"size": path.stat().st_size, "sha256": digest.hexdigest()}


def _offline(offline: bool) -> None:
    if not offline:
        raise BackupError("Stop all IAM writers and pass --offline to acknowledge the offline requirement.")


def create_backup(data_dir: Path, archive: Path, *, offline=False, factor_key_file: Path | None = None) -> None:
    """Snapshot stopped IAM state; exclusively publish a private, checksummed ZIP."""
    _offline(offline)
    _supported_platform()
    source, target = _path(data_dir), _path(archive)
    if not target.name.endswith(".iam-backup.zip"):
        raise BackupError("Backup output must end in .iam-backup.zip so credential archives remain Git-ignored.")
    if not source.is_dir() or not target.parent.is_dir() or target.exists():
        raise BackupError("Source/parent must exist and backup output must be a new path.")
    factor_path = Path(factor_key_file or os.getenv("IAM_FACTOR_KEY_FILE") or source / "factor-encryption.key")
    # Do not follow SQLite WAL/SHM links either; SQLite itself opens these files.
    database = _regular(source / "iam.sqlite3")
    for suffix in ("-wal", "-shm", "-journal"):
        _path(Path(str(database) + suffix))
    with _private_stage(target.parent, ".iam-backup-") as temporary:
        stage = temporary["path"]
        snapshot = stage / "iam.sqlite3"
        with _private_file(snapshot):
            pass
        with closing(_connect(database)) as original, closing(sqlite3.connect(snapshot)) as copied:
            deadline = time.monotonic() + 30
            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise BackupError("SQLite backup timed out; stop all writers and retry.")
            original.backup(copied, pages=256, progress=progress, sleep=0.05)
            # A standalone database needs no WAL sidecars in the archive.
            copied.execute("PRAGMA journal_mode=DELETE")
        _private_copy(source / "oidc-signing-key.pem", stage / "oidc-signing-key.pem", LIMITS["oidc-signing-key.pem"])
        _private_copy(factor_path, stage / "factor-encryption.key", LIMITS["factor-encryption.key"])
        members = set(REQUIRED)
        if (source / "deployment.json").exists() or (source / "deployment.json").is_symlink():
            _private_copy(source / "deployment.json", stage / "deployment.json", LIMITS["deployment.json"])
            members.add("deployment.json")
        metadata = _validate_state(stage)
        files = {name: _digest(stage / name) for name in sorted(members)}
        if any(info["size"] > LIMITS[name] for name, info in files.items()):
            raise BackupError("State exceeds supported backup size.")
        manifest = {"format": "adaptive-iam-state", "version": 1,
                    "created_at": datetime.now(timezone.utc).isoformat(), "files": files, "sqlite": metadata}
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        if len(manifest_bytes) > LIMITS["manifest.json"]:
            raise BackupError("SQLite metadata exceeds supported manifest size.")
        payload = stage / "state.zip"
        with _private_file(payload) as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                zipped.writestr("manifest.json", manifest_bytes)
                for name in sorted(members):
                    zipped.write(stage / name, arcname=name)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link publication is atomic and fails if another process claimed output.
        # Both paths share a filesystem. No existing backup can be replaced.
        os.link(payload, target)


def _extract(archive: Path, stage: Path) -> dict:
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        names = [entry.filename for entry in entries]
        if (len(names) != len(set(names)) or not (REQUIRED | {"manifest.json"}) <= set(names)
                or not set(names) <= (ALLOWED | {"manifest.json"})):
            raise BackupError("Archive has missing, duplicate or unsupported entries.")
        for entry in entries:
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (entry.is_dir() or kind not in (0, stat.S_IFREG) or entry.flag_bits & 1
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or not 0 < entry.file_size <= LIMITS[entry.filename]):
                raise BackupError("Archive contains an unsupported entry type or size.")
        manifest = _json(zipped.read("manifest.json"))
        if (not isinstance(manifest, dict) or set(manifest) != {"format", "version", "created_at", "files", "sqlite"}
                or manifest["format"] != "adaptive-iam-state" or type(manifest["version"]) is not int or manifest["version"] != 1
                or not isinstance(manifest["created_at"], str) or not isinstance(manifest["files"], dict)
                or set(manifest["files"]) != set(names) - {"manifest.json"}):
            raise BackupError("Archive manifest format is invalid.")
        for name, expected in manifest["files"].items():
            if (not isinstance(expected, dict) or set(expected) != {"size", "sha256"}
                    or type(expected["size"]) is not int or expected["size"] != zipped.getinfo(name).file_size
                    or not isinstance(expected["sha256"], str) or len(expected["sha256"]) != 64
                    or any(character not in "0123456789abcdef" for character in expected["sha256"])):
                raise BackupError("Archive manifest checksum/size is invalid.")
            with zipped.open(name) as incoming, _private_file(stage / name) as outgoing:
                remaining = expected["size"]
                digest = hashlib.sha256()
                while chunk := incoming.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise BackupError("Archive entry exceeds its declared size.")
                    outgoing.write(chunk)
                    digest.update(chunk)
                if remaining or digest.hexdigest() != expected["sha256"]:
                    raise BackupError("Archive checksum validation failed.")
        return manifest


def restore_backup(archive: Path, destination: Path, *, offline=False) -> None:
    """Validate every file in a private staging directory before atomic installation."""
    _offline(offline)
    _supported_platform()
    archive, target = _regular(archive), _path(destination)
    if target.exists() or not target.parent.is_dir():
        raise BackupError("Restore requires a new destination path with an existing parent.")
    with _private_stage(target.parent, ".iam-restore-") as temporary:
        stage = temporary["path"]
        manifest = _extract(archive, stage)
        if _validate_state(stage) != manifest["sqlite"]:
            raise BackupError("SQLite metadata does not match the manifest.")
        _publish_directory(stage, target)
        temporary["path"] = None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create", help="Back up stopped IAM state; output must not exist.")
    create.add_argument("--data-dir", type=Path, default=Path(os.getenv("IAM_DATA_DIR", str(ROOT / "backend" / "data"))))
    create.add_argument("--output", type=Path, required=True, help="New private archive ending in .iam-backup.zip.")
    create.add_argument("--factor-key-file", type=Path, help="Overrides IAM_FACTOR_KEY_FILE; included under canonical filename.")
    restore = subcommands.add_parser("restore", help="Validate and restore into a new, nonexistent directory.")
    restore.add_argument("--archive", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    for command in (create, restore):
        command.add_argument("--offline", action="store_true", required=True, help="Acknowledge all IAM writers are stopped.")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            create_backup(args.data_dir, args.output, offline=args.offline, factor_key_file=args.factor_key_file)
        else:
            restore_backup(args.archive, args.destination, offline=args.offline)
    except BackupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        # SQLite, JSON, archive and crypto exceptions can contain sensitive input.
        print("Backup/restore failed. Check paths, permissions, dependencies and archive integrity; no state was installed.", file=sys.stderr)
        return 1
    print("Backup created. Protect this unencrypted credential archive." if args.command == "create" else "State restored. Review runtime configuration before restarting IAM.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
