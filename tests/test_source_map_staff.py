import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAFF = ROOT / "data/staff-actuators"
LAUNCHER = STAFF / "caduceus-profile-sources-reseed"


def certificate() -> str:
    return '''{\n  "schema" : "homeserver.device-profile.v1",\n  "birth_provenance": { "born": "fixture" },\n  "hardware" : {"serial":"abc"},\n  "kernel": { "profile": "tv" },\n  "profile": "tv"\n}\n'''


def valid_map() -> dict:
    return {
        "caduceus": {
            "ref": "main",
            "candidates": [{"kind": "git", "url": "git@git.home.arpa:HOMESERVERSLTD/caduceus.git"}],
        },
        "keyman": {
            "ref": "v1",
            "candidates": [{"kind": "local-checkout", "path": "/opt/keyman/source"}],
        },
    }


def run(root: Path) -> tuple[int, dict, bytes]:
    env = os.environ | {"CADUCEUS_ROOT": str(root), "PYTHONPATH": str(STAFF)}
    out = subprocess.run(
        ["python3", "-m", "caduceus_staff.source_map", "reseed"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    return out.returncode, json.loads(out.stdout), (root / "etc/profile.json").read_bytes()


class SourceMapStaffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="caduceus-source-map-")
        self.root = Path(self.temp.name)
        (self.root / "etc/caduceus").mkdir(parents=True)
        (self.root / "etc/profile.json").write_text(certificate())
        (self.root / "etc/caduceus/source-map.json").write_text(json.dumps(valid_map()))

    def tearDown(self):
        self.temp.cleanup()

    def test_launcher_is_root_fixed_path_staff_wrapper(self):
        self.assertTrue(LAUNCHER.stat().st_mode & stat.S_IXUSR)
        text = LAUNCHER.read_text()
        self.assertIn('id -u', text)
        self.assertIn('caduceus_staff.source_map reseed', text)
        self.assertNotIn('profile.json "$@"', text)

    def test_splice_preserves_non_sources_bytes_mode_and_idempotence(self):
        before = (self.root / "etc/profile.json").read_text()
        rc, receipt, first = run(self.root)
        self.assertEqual(rc, 0)
        self.assertTrue(receipt["ok"])
        self.assertTrue(receipt["changed"])
        self.assertEqual(receipt["components"], ["caduceus", "keyman"])
        self.assertTrue(receipt["preservedNonSourcesBytes"])
        self.assertEqual(receipt["certificatePath"], "/etc/profile.json")
        self.assertEqual(receipt["sourceMapPath"], "/etc/caduceus/source-map.json")
        after_text = first.decode()
        for member in (
            '"birth_provenance": { "born": "fixture" }',
            '"hardware" : {"serial":"abc"}',
            '"kernel": { "profile": "tv" }',
            '"profile": "tv"',
        ):
            self.assertIn(member, before)
            self.assertIn(member, after_text)
        document = json.loads(first)
        self.assertEqual(document["sources"], valid_map())
        self.assertEqual(stat.S_IMODE((self.root / "etc/profile.json").stat().st_mode), 0o444)

        rc, receipt, second = run(self.root)
        self.assertEqual(rc, 0)
        self.assertTrue(receipt["ok"])
        self.assertFalse(receipt["changed"])
        self.assertEqual(first, second)

    def test_malformed_map_refuses_before_certificate_write(self):
        before = (self.root / "etc/profile.json").read_bytes()
        (self.root / "etc/caduceus/source-map.json").write_text(json.dumps({
            "caduceus": {"ref": "main", "candidates": [{"kind": "git", "url": "https://token@example.invalid/repo.git"}]}
        }))
        rc, receipt, after = run(self.root)
        self.assertEqual(rc, 1)
        self.assertFalse(receipt["ok"])
        self.assertIn("credential-material-forbidden", receipt["firstMissingSignal"])
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
