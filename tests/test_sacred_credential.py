import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

STAFF = Path(__file__).parents[1] / "data" / "staff-actuators"
sys.path.insert(0, str(STAFF))
from caduceus_staff import bind_derived, sacred_credential  # noqa: E402

KEYMAN = Path("/fulcrum/attachments/keyman")
SKELETON = b"caduceus-fixture-skeleton-v1\x00bytes\nraw-tail"
IDENTITY = hashlib.sha256(SKELETON).hexdigest()
PIN = "2468"
NEW_PIN = "9753"


class SacredCredentialProgramTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.keys = root / "key"
        self.vault = root / "vault/.keys"
        self.runtime = root / "runtime"
        self.keys.mkdir(parents=True)
        self.vault.mkdir(parents=True)
        self.runtime.mkdir()
        (self.keys / "skeleton.key").write_bytes(SKELETON)
        self.fake_crypto = self.runtime / "keyman-crypto"
        self.fake_crypto.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import os
            import re
            import sys
            from pathlib import Path

            vault = Path(os.environ["CADUCEUS_KEYMAN_VAULT_DIR"])
            operation, input_path = sys.argv[1:3]
            fields = dict(line.split("=", 1) for line in Path(input_path).read_text().splitlines() if "=" in line)
            target = vault / (fields.get("service", "caduceus") + ".key")
            if operation == "create":
                target.write_text('username="%s"\\npassword="%s"\\n' % (fields["username"], fields["password"]))
            elif operation == "decrypt":
                Path(sys.argv[3]).write_bytes(target.read_bytes())
            elif operation == "reencrypt":
                record = target.read_text()
                username = re.search(r'^username="([^"\\n]+)"$', record, re.M).group(1)
                target.write_text('username="%s"\\npassword="%s"\\n' % (username, fields["new_password"]))
            else:
                raise SystemExit(4)
        """), encoding="utf-8")
        self.fake_crypto.chmod(0o700)
        self.env = {
            "CADUCEUS_KEYMAN_KEY_DIR": str(self.keys),
            "CADUCEUS_KEYMAN_VAULT_DIR": str(self.vault),
            "CADUCEUS_KEYMAN_CRYPTO": str(self.fake_crypto),
            "CADUCEUS_KEYMAN_TEMP_DIR": str(self.runtime),
        }
        self.root = mock.patch.object(sacred_credential, "_require_root")
        self.root.start()
        self.patch = mock.patch.dict(os.environ, self.env, clear=False)
        self.patch.start()
        bind_derived._BOUND = None
        sacred_credential.provision_caduceus(PIN)

    def tearDown(self):
        bind_derived._BOUND = None
        self.patch.stop()
        self.root.stop()
        self.temp.cleanup()

    def test_raw_identity_and_keyman_only_seat_verify_rotate_and_unbound(self):
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

    def test_custody_adapter_contains_no_python_cipher_or_kdf(self):
        source = (STAFF / "caduceus_staff/sacred_credential.py").read_text(encoding="utf-8")
        forbidden = ["hazmat.primitives.ciphers", "hazmat.primitives.kdf", "_decrypt_openssl", "_encrypt_openssl"]
        for term in forbidden:
            self.assertNotIn(term, source)
        self.assertIn('"decrypt"', source)
        self.assertIn('"reencrypt"', source)
        self.assertIn("subprocess.run", source)

    @unittest.skipUnless(Path("/usr/bin/unshare").is_file(), "requires unprivileged user/mount namespace support")
    def test_bind_succeeds_for_key_seated_by_real_newkey(self):
        """Exercise real Keyman crypto + newkey.sh under a mount-isolated fake root."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "root/key").mkdir(parents=True)
            (root / "vault/.keys").mkdir(parents=True)
            (root / "tmp").mkdir()
            (root / "dev").mkdir()
            (root / "mnt/keyexchange").mkdir(parents=True)
            (root / "dev/null").write_bytes(b"")
            (root / "root/key/skeleton.key").write_bytes(SKELETON)
            for source in (KEYMAN / "keyman-crypto", KEYMAN / "newkey.sh"):
                target = root / "vault/keyman" / source.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                target.chmod(0o700)
            (root / "vault/keyman/utils.sh").write_text(textwrap.dedent("""\
                readonly VAULT_DIR="/vault/.keys"
                time_operation() { "$@"; }
                init_ramdisk() { return 0; }
                secure_cleanup() { return 0; }
                error_exit() { echo "ERROR: $1" >&2; exit 1; }
            """), encoding="utf-8")
            for executable in (Path("/bin/bash"), KEYMAN / "keyman-crypto"):
                for candidate in (executable, *[Path(value) for value in re.findall(r"(?:=> )?(/[^ ]+)", subprocess.check_output(["ldd", str(executable)], text=True))]):
                    target = root / candidate.relative_to("/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.exists():
                        shutil.copy2(candidate, target)
            for command in ("mountpoint", "shred", "umount", "rmdir", "ls"):
                target = root / "bin" / command
                target.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
                target.chmod(0o700)
            identity = hashlib.sha256(SKELETON).hexdigest()
            helper = textwrap.dedent("""\
                import json, os, sys
                sys.path.insert(0, sys.argv[4])
                from caduceus_staff.sacred_credential import bind_derived_caduceus
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                Ed25519PrivateKey.from_private_bytes(bytes(32))
                root, identity, pin = sys.argv[1:4]
                os.chroot(root); os.chdir("/")
                os.environ["PATH"] = "/bin"
                os.environ["CADUCEUS_KEYMAN_TEMP_DIR"] = "/tmp"
                for name in ("CADUCEUS_KEYMAN_KEY_DIR", "CADUCEUS_KEYMAN_VAULT_DIR", "CADUCEUS_KEYMAN_CRYPTO"):
                    os.environ.pop(name, None)
                with open("/tmp/service-suite-input", "w", encoding="utf-8") as handle:
                    handle.write('username="service_suite"\\npassword="fixture-suite-password"\\n')
                import subprocess
                subprocess.run(["/vault/keyman/keyman-crypto", "encrypt_suite_key", "/tmp/service-suite-input"], check=True, stdout=subprocess.DEVNULL)
                created = subprocess.run(["/vault/keyman/newkey.sh", "caduceus", identity, pin], check=True, text=True, capture_output=True)
                if not os.path.isfile("/vault/.keys/caduceus.key"):
                    raise RuntimeError("newkey did not seat caduceus: " + created.stdout + created.stderr)
                with bind_derived_caduceus() as signer:
                    print(json.dumps({"identity": signer.identity_sha256, "public": signer.public_key_hex}))
            """)
            result = subprocess.run(
                ["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--pid", "--fork", "python3", "-c", helper, str(root), identity, PIN, str(STAFF)],
                check=False,
                text=True,
                capture_output=True,
                timeout=45,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            projection = json.loads(result.stdout)
            self.assertEqual(projection["identity"], identity)
            self.assertEqual(len(projection["public"]), 64)
            self.assertTrue((root / "vault/.keys/caduceus.key").is_file())


if __name__ == "__main__":
    unittest.main()
