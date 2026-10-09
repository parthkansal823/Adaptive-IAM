"""Verify the checksum manifest without loading research binaries into context."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    manifest = json.loads((ROOT / "research/assets-manifest.json").read_text(encoding="utf-8-sig"))
    errors = []
    for entry in manifest:
        path = (ROOT / entry["current_path"]).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            errors.append(f"Missing or invalid asset: {entry['current_path']}")
            continue
        checksum = hashlib.sha256()
        with path.open("rb") as asset:
            for chunk in iter(lambda: asset.read(1024 * 1024), b""):
                checksum.update(chunk)
        if checksum.hexdigest() != entry["sha256"] or path.stat().st_size != entry["bytes"]:
            errors.append(f"Checksum/size mismatch: {entry['current_path']}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Research integrity: {len(manifest)} preserved assets verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

