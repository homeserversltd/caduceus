import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAFF = ROOT / "data/staff-actuators"


class HouseholdCapabilityStaffDataTests(unittest.TestCase):
    def test_catalog_registers_household_capability(self):
        profile = json.loads((STAFF / "profile.json").read_text())
        actuator = next(item for item in profile["actuators"] if item["id"] == "household-capability")
        self.assertEqual(actuator["actuatorClass"], "staff-python")
        self.assertEqual(actuator["pythonModule"], "caduceus_staff.household_capability")
        self.assertEqual(actuator["receiptFamily"], "caduceus.household.capability.v1")

    def test_band_has_ordered_digest_child_and_module_face(self):
        band = STAFF / "caduceus_staff/household_capability"
        metadata = json.loads((band / "index.json").read_text())
        self.assertEqual(metadata["children"], ["skeleton-sha"])
        for relative in ("index.py", "__init__.py", "__main__.py", "skeleton_sha/index.py"):
            self.assertTrue((band / relative).is_file(), relative)

    def test_digest_helper_is_fixed_path_and_zero_argument(self):
        helper = (STAFF / "caduceus-skeleton-sha").read_text()
        self.assertIn('[ "$#" -eq 0 ]', helper)
        self.assertIn("/root/key/skeleton.key", helper)
        self.assertNotIn('"$1"', helper)


if __name__ == "__main__":
    unittest.main()
