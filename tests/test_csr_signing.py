import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data/staff-actuators"))
from caduceus_staff import house_ca


class CsrSigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="caduceus-csr-")
        self.env = os.environ.copy()
        self.env["CADUCEUS_ROOT"] = self.temp.name
        self.old = os.environ.get("CADUCEUS_ROOT")
        os.environ["CADUCEUS_ROOT"] = self.temp.name
        appliance = Path(self.temp.name) / "etc/appliance"
        appliance.mkdir(parents=True)
        (appliance / "profile.json").write_text(
            '{"fqdn":"fixture-csr.home.arpa","ip":"192.0.2.42"}\n'
        )
        house_ca.ensure_root()
        self.req = Path(self.temp.name) / "req"
        self.req.mkdir()
        config = self.req / "req.cnf"
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n"
            "[dn]\nCN=fixture-csr.home.arpa\n"
            "[ext]\nsubjectAltName=DNS:fixture-csr.home.arpa,IP:192.0.2.42\n"
        )
        subprocess.run(
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.req / "key.pem"), "-out", str(self.req / "request.pem"),
             "-config", str(config)], check=True, capture_output=True
        )
        self.csr = (self.req / "request.pem").read_text()

    def tearDown(self):
        if self.old is None:
            os.environ.pop("CADUCEUS_ROOT", None)
        else:
            os.environ["CADUCEUS_ROOT"] = self.old
        self.temp.cleanup()

    def test_valid_csr_returns_only_leaf_ca_and_fingerprints(self):
        receipt = house_ca.sign_csr(self.csr)
        self.assertEqual(receipt["schema"], "caduceus.staff.house_ca.csr_sign.v1")
        self.assertIn("BEGIN CERTIFICATE", receipt["leaf_pem"])
        self.assertIn("BEGIN CERTIFICATE", receipt["ca_pem"])
        self.assertNotIn("PRIVATE KEY", str(receipt))
        self.assertNotIn("key_path", receipt)
        self.assertNotIn("certificate", receipt)
        self.assertTrue(receipt["changed"])
        self.assertEqual(receipt["identity"], "fixture-csr.home.arpa")
        self.assertEqual(receipt["sans"], ["fixture-csr.home.arpa", "192.0.2.42"])

    def test_malformed_san_identity_and_oversized_requests_refuse(self):
        wrong_config = self.req / "wrong.cnf"
        wrong_config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n"
            "[dn]\nCN=fixture-csr.home.arpa\n"
            "[ext]\nsubjectAltName=DNS:fixture-csr.home.arpa,IP:192.0.2.10\n"
        )
        subprocess.run(
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(self.req / "wrong-key.pem"),
             "-out", str(self.req / "wrong-request.pem"), "-config", str(wrong_config)],
            check=True, capture_output=True
        )
        wrong_csr = (self.req / "wrong-request.pem").read_text()
        for value, expected in [
            ("not a csr", "caduceus-cert-csr-invalid"),
            (wrong_csr, "caduceus-cert-csr-san-mismatch"),
            ("x" * (house_ca.CSR_MAX_BYTES + 1), "caduceus-cert-csr-too-large"),
        ]:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ValueError, expected):
                    house_ca.sign_csr(value)

    def test_private_key_and_control_characters_never_enter_openssl(self):
        for value in ["-----BEGIN PRIVATE KEY-----", self.csr + "\x00"]:
            with self.assertRaisesRegex(ValueError, "private-key-or-control"):
                house_ca.sign_csr(value)

    def test_missing_root_refuses_without_bootstrapping(self):
        empty = Path(self.temp.name) / "empty-root"
        empty.mkdir()
        os.environ["CADUCEUS_ROOT"] = str(empty)
        with self.assertRaisesRegex(RuntimeError, "caduceus-house-ca-unavailable"):
            house_ca.sign_csr(self.csr)
        self.assertFalse((empty / "var/lib/caduceus/certs/ca.pem").exists())


if __name__ == "__main__":
    unittest.main()
