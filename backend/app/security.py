"""Server-observed context and RFC 6238 primitives; no client risk claims."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import struct
import time
from pathlib import Path

from cryptography.fernet import Fernet


def totp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}"


def matching_counter(secret: str, code: str | None, previous: int = -1) -> int | None:
    if not code or len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int(time.time()) // 30
    for counter in (current, current-1, current+1):
        if counter > previous and hmac.compare_digest(totp(secret, counter), code):
            return counter
    return None


class ContextSecurity:
    def __init__(self, data_dir: Path):
        self.demo_mode = os.getenv("IAM_DEMO_MODE", "true").lower() == "true"
        self.trusted_proxies = set()
        for value in os.getenv("IAM_TRUSTED_PROXY_IPS", "").split(","):
            if value.strip():
                self.trusted_proxies.add(str(ipaddress.ip_address(value.strip())))
        # A dedicated runtime key, separate from OAuth signing keys. Secrets never enter audit.
        path = Path(os.getenv("IAM_FACTOR_KEY_FILE", str(data_dir / "factor-encryption.key")))
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(Fernet.generate_key())
            except FileExistsError:
                pass
        self.key = path.read_bytes()
        self.cipher = Fernet(self.key)

    def client_ip(self, request):
        address = request.client.host if request.client else "unknown"
        # Exactly one trusted proxy and one validated address; arbitrary chains are ignored.
        if address in self.trusted_proxies:
            forwarded = request.headers.get("x-forwarded-for", "")
            if "," not in forwarded:
                try:
                    return str(ipaddress.ip_address(forwarded.strip()))
                except ValueError:
                    pass
        return address

    def fingerprint(self, request):
        address = self.client_ip(request)
        agent = request.headers.get("user-agent", "")[:512]
        return hmac.new(self.key, (address + "\0" + agent).encode(), hashlib.sha256).hexdigest()
