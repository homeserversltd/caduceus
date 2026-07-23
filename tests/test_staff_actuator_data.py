import json
import stat
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAFF = ROOT / "data/staff-actuators"


class StaffActuatorDataTests(unittest.TestCase):
    def test_sacred_credential_is_the_only_pin_authority_module(self):
        module = STAFF / "caduceus_staff/sacred_credential.py"
        self.assertTrue(module.is_file())
        self.assertFalse((STAFF / "caduceus_staff/household_capability").exists())
        self.assertFalse((STAFF / "caduceus-skeleton-sha").exists())

    def test_legacy_capability_launchers_are_absent(self):
        self.assertFalse((STAFF / "caduceus-keyman-sign-capability").exists())
        self.assertFalse((STAFF / "caduceus-keyman-rotate-capability").exists())

    def test_bind_launchers_set_staff_import_path_under_env_reset(self):
        commands = {
            "bind": "bind",
            "verify": "verify",
            "atomic-change-pin": "atomic-change-pin",
        }
        for launcher, command in commands.items():
            path = STAFF / launcher
            self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
            text = path.read_text()
            self.assertIn("export PYTHONPATH=/usr/local/sbin", text)
            self.assertIn(f"caduceus_staff.bind_derived {command}", text)


if __name__ == "__main__":
    unittest.main()
