import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data/staff-actuators"))
from caduceus_staff import house_ca


class BundleReadTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="caduceus-bundle-read-")
        return temporary, mock.patch.dict(
            os.environ,
            {"CADUCEUS_ROOT": temporary.name, "PYTHONDONTWRITEBYTECODE": "1"},
            clear=False,
        )

    @staticmethod
    def snapshot(root: Path):
        return {
            str(path.relative_to(root)): (path.stat().st_mtime_ns, path.stat().st_size)
            for path in root.rglob("*")
            if path.is_file()
        }

    def test_each_platform_has_deterministic_public_receipt(self):
        temporary, environment = self.fixture()
        with temporary, environment:
            root = Path(temporary.name)
            house_ca.ensure_root()
            for platform in sorted(house_ca.PLATFORMS):
                exported = house_ca.bundle_export(platform)
                before = self.snapshot(root)
                receipt = house_ca.bundle_read(platform)
                self.assertEqual(before, self.snapshot(root))
                suffix = ".cer" if platform == "windows" else ".crt"
                filename = f"homeserver-house-ca-{platform}{suffix}"
                self.assertEqual(receipt["schema"], "caduceus.staff.house_ca.bundle_read.v1")
                self.assertEqual(receipt["filename"], filename)
                self.assertEqual(receipt["mime_type"], "application/x-x509-ca-cert")
                self.assertEqual(receipt["platform"], platform)
                self.assertFalse(receipt["changed"])
                self.assertFalse(receipt["client_reinstall_required"])
                self.assertNotIn("path", receipt)
                content = base64.b64decode(receipt["content_base64"], validate=True)
                self.assertEqual(content, Path(exported["path"]).read_bytes())
                self.assertNotIn(b"PRIVATE KEY", content)
                self.assertTrue(receipt["fingerprint"])

    def test_absent_and_path_shaped_platforms_refuse_without_state_creation(self):
        temporary, environment = self.fixture()
        with temporary, environment:
            root = Path(temporary.name)
            before = self.snapshot(root)
            with self.assertRaisesRegex(ValueError, "caduceus-cert-bundle-missing"):
                house_ca.bundle_read("linux")
            self.assertEqual(before, self.snapshot(root))
            self.assertFalse((root / "var/lib/caduceus/certs").exists())
            for hostile in ("../../etc/passwd", "/tmp/root.crt", "linux/../../ca.key.pem", "plan9"):
                with self.subTest(hostile=hostile):
                    with self.assertRaisesRegex(ValueError, "caduceus-cert-platform-invalid"):
                        house_ca.bundle_read(hostile)
            self.assertEqual(before, self.snapshot(root))

    def test_private_key_marker_refuses_before_certificate_parsing(self):
        temporary, environment = self.fixture()
        with temporary, environment:
            root = Path(temporary.name)
            bundle = root / "var/lib/caduceus/certs/bundles/homeserver-house-ca-linux.crt"
            bundle.parent.mkdir(parents=True)
            bundle.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot-public\n")
            before = self.snapshot(root)
            with self.assertRaisesRegex(RuntimeError, "caduceus-cert-private-key-leaked"):
                house_ca.bundle_read("linux")
            self.assertEqual(before, self.snapshot(root))
            self.assertFalse((root / "var/lib/caduceus/certs/ca.pem").exists())
            self.assertFalse((root / "var/lib/caduceus/certs/ca.key.pem").exists())


if __name__ == "__main__":
    unittest.main()
