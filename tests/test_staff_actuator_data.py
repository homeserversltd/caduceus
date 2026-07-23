import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAFF = ROOT / "data/staff-actuators"


class StaffActuatorDataTests(unittest.TestCase):
    def test_bind_derived_keeps_ordered_digest_child(self):
        band = STAFF / "caduceus_staff/household_capability"
        metadata = json.loads((band / "index.json").read_text())
        self.assertEqual(metadata["children"], ["skeleton-sha"])
        self.assertTrue((band / "skeleton_sha/index.py").is_file())

    def test_digest_helper_is_fixed_path_and_zero_argument(self):
        helper = (STAFF / "caduceus-skeleton-sha").read_text()
        self.assertIn('[ "$#" -eq 0 ]', helper)
        self.assertIn("/root/key/skeleton.key", helper)
        self.assertNotIn('"$1"', helper)


if __name__ == "__main__":
    unittest.main()
