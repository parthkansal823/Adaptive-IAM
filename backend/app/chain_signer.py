"""Narrow private-network signer client; never possesses an Ethereum writer key."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def permitted_signer(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == "http" and parsed.hostname == "registry-signer"
                and parsed.port == 9100 and parsed.path in {"", "/"}
                and not parsed.username and not parsed.password
                and not parsed.query and not parsed.fragment)
    except ValueError:
        return False


class RegistrySigner:
    def __init__(self, url: str, token_file: Path):
        if not permitted_signer(url):
            raise RuntimeError("Only the exact private registry-signer:9100 service is allowed")
        self.url, self.token_file = url.rstrip("/"), token_file

    def call(self, path: str, payload=None):
        if path not in {"/registry", "/transaction"}:
            raise RuntimeError("Unsupported signer operation")
        headers = {"Content-Type": "application/json"}
        if payload is not None:
            token = self.token_file.read_text(encoding="utf-8").strip()
            if len(token) != 64:
                raise RuntimeError("Missing private signer authentication credential")
            headers["Authorization"] = "Bearer " + token
        request = Request(self.url + path, data=None if payload is None else json.dumps(payload).encode(), headers=headers)
        with urlopen(request, timeout=15) as response:
            result = json.loads(response.read(16384))
        if not isinstance(result, dict):
            raise RuntimeError("Invalid private signer response")
        return result

    def registry(self):
        return self.call("/registry")

    def submit(self, kind: str, arguments):
        if kind not in {"audit", "audit_batch", "grant", "revoke"}:
            raise RuntimeError("Signer can only checkpoint events/batches, grant or revoke the fixed registry")
        return self.call("/transaction", {"kind": kind, "arguments": arguments})
