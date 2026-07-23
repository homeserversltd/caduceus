import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

STAFF = Path(__file__).parents[1] / "data" / "staff-actuators"
sys.path.insert(0, str(STAFF))
from caduceus_staff import bind_derived, sacred_credential  # noqa: E402

SKELETON = bytes.fromhex("63616475636575732d666978747572652d736b656c65746f6e2d7631006279746573")
IDENTITY = "911ec7c51dbfff3d9e8d45c80895fd9eb01a1c0a211046eb066564a77a914811"
PIN = "2468"
NEW_PIN = "9753"
SUITE_PASSWORD = b"service-suite-fixture-password"


def encrypt(plaintext: bytes, password: bytes, salt: bytes) -> bytes:
    key_iv = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt, iterations=10_000).derive(password)
    pad = 16 - len(plaintext) % 16
    encryptor = Cipher(algorithms.AES(key_iv[:32]), modes.CBC(key_iv[32:])).encryptor()
    return b"Salted__" + salt + encryptor.update(plaintext + bytes([pad]) * pad) + encryptor.finalize()


class SacredCredentialProgramTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.keys = root / "key"
        self.vault = root / "vault/.keys"
        self.keys.mkdir(parents=True)
        self.vault.mkdir(parents=True)
        (self.keys / "skeleton.key").write_bytes(SKELETON)
        (self.vault / "service_suite.key").write_bytes(encrypt(
            b'username="service_suite"\npassword="service-suite-fixture-password"\n', SKELETON.split(b"\x00", 1)[0], b"suite123"
        ))
        self.write_pin(PIN)
        self.env = {
            "CADUCEUS_KEYMAN_KEY_DIR": str(self.keys),
            "CADUCEUS_KEYMAN_VAULT_DIR": str(self.vault),
        }
        self.root = mock.patch.object(sacred_credential, "_require_root")
        self.root.start()
        self.patch = mock.patch.dict(os.environ, self.env, clear=False)
        self.patch.start()
        bind_derived._BOUND = None

    def tearDown(self):
        bind_derived._BOUND = None
        self.patch.stop()
        self.root.stop()
        self.temp.cleanup()

    def write_pin(self, pin: str):
        (self.vault / "caduceus.key").write_bytes(encrypt(
            f'username="{IDENTITY}"\npassword="{pin}"\n'.encode(), SUITE_PASSWORD, b"caduceus"
        ))

    def test_seat_verify_rotate_and_unbound(self):
        seated = bind_derived.bind_derived()
        self.assertTrue(seated["ok"])
        self.assertEqual(seated["identity"], IDENTITY)
        self.assertEqual(seated["posture"], "DERIVED_BOUND")
        self.assertTrue(bind_derived.verify_derived(PIN)["ok"])
        wrong = bind_derived.verify_derived("wrong")
        self.assertFalse(wrong["ok"])
        self.assertEqual(wrong["firstMissingSignal"], "caduceus-pin-refused")
        before = seated["publicKey"]
        changed = bind_derived.atomic_change_pin(PIN, NEW_PIN)
        self.assertTrue(changed["ok"])
        self.assertTrue(changed["rotated"])
        self.assertNotEqual(changed["publicKey"], before)
        self.assertFalse(bind_derived.verify_derived(PIN)["ok"])
        self.assertTrue(bind_derived.verify_derived(NEW_PIN)["ok"])
        bind_derived._BOUND = None
        (self.vault / "caduceus.key").unlink()
        absent = bind_derived.bind_derived()
        self.assertFalse(absent["ok"])
        self.assertEqual(absent["posture"], "UNBOUND")
        self.assertEqual(absent["firstMissingSignal"], "caduceus-pin-not-yet-provisioned")


if __name__ == "__main__":
    unittest.main()
