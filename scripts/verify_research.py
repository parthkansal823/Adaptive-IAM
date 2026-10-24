"""Verify the checksum manifest without loading research binaries into context."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MIN_ORIGINAL_ASSETS = 31


def verify_manifest(root: Path, manifest) -> list[str]:
    """Reject incomplete/malformed manifests as well as changed asset bytes."""
    errors = []
    if not isinstance(manifest, list) or len(manifest) < MIN_ORIGINAL_ASSETS:
        return [f"Research manifest must retain at least {MIN_ORIGINAL_ASSETS} original assets."]
    root = root.resolve()
    research = (root / "research").resolve()
    paths, originals = set(), set()
    for index, entry in enumerate(manifest, start=1):
        if (not isinstance(entry, dict)
                or not isinstance(entry.get("current_path"), str) or not entry["current_path"]
                or not isinstance(entry.get("original_path"), str) or not entry["original_path"]
                or not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                or type(entry.get("bytes")) is not int or entry["bytes"] < 0):
            errors.append(f"Invalid research manifest entry at position {index}.")
            continue
        path = (root / entry["current_path"]).resolve()
        if path in paths or entry["original_path"] in originals:
            errors.append(f"Duplicate research manifest asset at position {index}.")
            continue
        paths.add(path)
        originals.add(entry["original_path"])
        if not path.is_relative_to(research) or not path.is_file():
            errors.append(f"Missing or invalid asset: {entry['current_path']}")
            continue
        checksum = hashlib.sha256()
        with path.open("rb") as asset:
            for chunk in iter(lambda: asset.read(1024 * 1024), b""):
                checksum.update(chunk)
        if checksum.hexdigest() != entry["sha256"] or path.stat().st_size != entry["bytes"]:
            errors.append(f"Checksum/size mismatch: {entry['current_path']}")
    return errors


def main() -> int:
    try:
        manifest = json.loads((ROOT / "research/assets-manifest.json").read_text(encoding="utf-8-sig"))
        errors = verify_manifest(ROOT, manifest)
    except (OSError, ValueError):
        print("Research integrity verification could not read valid manifest/asset files.", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Research integrity: {len(manifest)} preserved assets verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

