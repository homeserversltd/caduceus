"""Digest-only access to the fixed household skeleton identity."""
from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

SKELETON_PATH = Path("/root/key/skeleton.key")
HELPER = "/usr/local/sbin/caduceus-skeleton-sha"

def _test_path() -> Path | None:
    value = os.environ.get("CADUCEUS_TEST_SKELETON_PATH")
    return Path(value) if value else None

def skeleton_sha() -> str:
    fixture = _test_path()
    if fixture is not None:
        return hashlib.sha256(fixture.read_bytes()).hexdigest()
    if os.geteuid() == 0:
        return hashlib.sha256(SKELETON_PATH.read_bytes()).hexdigest()
    result = subprocess.run(["sudo", HELPER], check=True, text=True, capture_output=True)
    digest = result.stdout.strip()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError("caduceus-skeleton-sha-invalid-digest")
    return digest

def skeleton_sha_receipt() -> dict[str, Any]:
    return {"ok": True, "digest": skeleton_sha(), "algorithm": "sha256", "firstMissingSignal": "none"}

def main(argv: list[str] | None = None) -> int:
    if argv:
        raise SystemExit("caduceus-skeleton-sha-accepts-no-arguments")
    print(skeleton_sha())
    return 0
