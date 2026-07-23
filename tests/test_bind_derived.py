import hashlib
import sys
from pathlib import Path

STAFF = Path(__file__).parents[1] / "data" / "staff-actuators"
sys.path.insert(0, str(STAFF))
from caduceus_staff.bind_derived import identity_hex, seed_bytes  # noqa: E402


def test_bind_derived_exact_seed_math():
    raw = b"active leaf\x00\xff"
    identity = hashlib.sha256(raw).hexdigest()
    expected = hashlib.sha256(identity.encode("ascii") + b"\x00" + "päss".encode("utf-8")).digest()
    assert identity_hex(raw) == identity
    assert seed_bytes(identity, "päss") == expected
