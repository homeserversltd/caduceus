import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
STAFF = ROOT / "data/staff-actuators"
sys.path.insert(0, str(STAFF))

from caduceus_staff.network import dns


class DnsActuatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "unbound.conf"
        self.path.write_bytes(b"server:\n  verbosity: 1\n# keep me\n")
        os.chmod(self.path, 0o640)

    def tearDown(self):
        self.temp.cleanup()

    def call(self, intent, **kwargs):
        return dns.dispatch(intent, config_path=self.path, checkconf=lambda path: (True, ""), **kwargs)

    def test_ensure_inserts_exact_record_and_preserves_bytes(self):
        before = self.path.read_bytes()
        receipt = self.call({"action": "ensure-local-data", "name": "Media.HOME.arpa", "address": "192.168.1.20"})
        self.assertTrue(receipt["ok"])
        self.assertTrue(receipt["changed"])
        self.assertEqual(self.path.read_bytes(), before + b'local-data: "media.home.arpa. A 192.168.1.20"\n')
        self.assertEqual(receipt["serviceAction"], "not-owned")
        self.assertNotIn("verbosity", json.dumps(receipt))

    def test_ensure_replaces_one_exact_name_and_refuses_duplicate_target(self):
        self.path.write_bytes(b'server:\n# keep\nlocal-data: "app.home.arpa. A 192.168.1.2"\nlocal-data: "other.home.arpa. A 192.168.1.3"\n')
        receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.9"})
        self.assertTrue(receipt["changed"])
        self.assertEqual(self.path.read_bytes(), b'server:\n# keep\nlocal-data: "app.home.arpa. A 192.168.1.9"\nlocal-data: "other.home.arpa. A 192.168.1.3"\n')
        duplicate = self.path.read_bytes() + b'local-data: "app.home.arpa. A 192.168.1.4"\n'
        self.path.write_bytes(duplicate)
        refused = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.5"})
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["error"], "dns-target-record-ambiguous")
        self.assertEqual(self.path.read_bytes(), duplicate)

    def test_remove_is_idempotent_and_preserves_unrelated_bytes(self):
        original = b'server:\n# keep\nlocal-data: "app.home.arpa. A 192.168.1.2"\nlocal-data: "other.home.arpa. A 192.168.1.3"\n'
        self.path.write_bytes(original)
        first = self.call({"action": "remove", "name": "app.home.arpa"})
        self.assertTrue(first["changed"])
        self.assertEqual(self.path.read_bytes(), b'server:\n# keep\nlocal-data: "other.home.arpa. A 192.168.1.3"\n')
        second = self.call({"action": "remove", "name": "app.home.arpa"})
        self.assertTrue(second["ok"])
        self.assertFalse(second["changed"])

    def test_server_section_insertion_precedes_forward_zone_and_preserves_neighbors(self):
        before = (
            b"server:\n"
            b"  verbosity: 1\n"
            b'  local-zone: "home.arpa." static\n'
            b'  local-data: "old.home.arpa. A 192.168.1.9"\n'
            b"  include-toplevel: \"/etc/unbound/local.conf\"\n"
            b"forward-zone:\n"
            b'  name: "."\n'
            b'  forward-addr: 1.1.1.1\n'
        )
        self.path.write_bytes(before)
        candidates = []
        receipt = dns.dispatch(
            {"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"},
            config_path=self.path,
            checkconf=lambda path: (candidates.append(Path(path).read_bytes()) or True, ""),
        )
        expected = before.replace(
            b"  include-toplevel:",
            b'  local-data: "app.home.arpa. A 192.168.1.2"\n  include-toplevel:',
        )
        self.assertTrue(receipt["ok"])
        self.assertEqual(self.path.read_bytes(), expected)
        self.assertEqual(candidates[0], expected)
        self.assertEqual(self.path.read_bytes().split(b"forward-zone:")[1], before.split(b"forward-zone:")[1])

    def test_status_validates_actual_file_and_scopes_records_to_server(self):
        self.path.write_bytes(
            b"server:\n"
            b'  local-data: "app.home.arpa. A 192.168.1.2"\n'
            b"forward-zone:\n"
            b'  local-data: "foreign.home.arpa. A 192.168.1.3"\n'
        )
        calls = []
        with mock.patch.object(os, "replace", wraps=os.replace) as replace:
            status = dns.dispatch({"action": "status"}, config_path=self.path, checkconf=lambda path: (calls.append(Path(path)) or True, ""))
            ensure = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertTrue(status["ok"])
        self.assertEqual(calls, [self.path])
        self.assertEqual(status["validation"], "installed-validated")
        self.assertEqual(status["records"], [{"name": "app.home.arpa.", "address": "192.168.1.2"}])
        self.assertFalse(ensure["changed"])
        replace.assert_not_called()

    def test_parent_directory_lock_spans_replacement_and_rollback(self):
        before = self.path.read_bytes()
        locked_kinds = []
        real_flock = dns.fcntl.flock
        def record_lock(fd, operation):
            locked_kinds.append(stat.S_IFMT(os.fstat(fd).st_mode))
            return real_flock(fd, operation)
        checks = []
        def validator(path):
            checks.append(Path(path).read_bytes())
            return (len(checks) != 2, "bad-installed" if len(checks) == 2 else "")
        with mock.patch.object(dns.fcntl, "flock", side_effect=record_lock):
            receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=validator)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "restored")
        self.assertIn(stat.S_IFDIR, locked_kinds)
        self.assertEqual(self.path.read_bytes(), before)

    def test_rollback_refuses_foreign_replacement_after_install(self):
        before = self.path.read_bytes()
        foreign = b"server:\n# foreign writer\n"
        calls = []
        def validator(path):
            calls.append(Path(path).read_bytes())
            if len(calls) == 2:
                replacement = self.root / "foreign.conf"
                replacement.write_bytes(foreign)
                os.replace(replacement, self.path)
                return False, "bad-installed"
            return True, ""
        receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=validator)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "refused-identity-changed")
        self.assertEqual(self.path.read_bytes(), foreign)
        self.assertNotEqual(self.path.read_bytes(), before)

    def test_write_all_handles_short_writes(self):
        writes = []
        def short_write(_fd, remaining):
            writes.append(remaining)
            return min(2, len(remaining))
        with mock.patch.object(dns.os, "write", side_effect=short_write):
            dns._write_all(99, b"abcdef")
        self.assertEqual(writes, [b"abcdef", b"cdef", b"ef"])

    def test_refuses_bad_intent_name_address_and_injection(self):
        for intent in (
            {}, {"action": "ensure-local-data", "name": "home.arpa", "address": "192.168.1.2"},
            {"action": "ensure-local-data", "name": "x.home.arpa; include: evil", "address": "192.168.1.2"},
            {"action": "ensure-local-data", "name": "x.home.arpa", "address": "8.8.8.8"},
            {"action": "ensure-local-data", "name": "x.home.arpa", "address": "127.0.0.1"},
            {"action": "ensure-local-data", "name": "x.home.arpa", "address": "255.255.255.255"},
            {"action": "remove", "name": "../x.home.arpa"},
        ):
            receipt = self.call(intent)
            self.assertFalse(receipt["ok"])
            self.assertFalse(receipt["changed"])
            self.assertNotIn("server:", json.dumps(receipt))

    def test_mixed_newlines_are_explicitly_refused_before_mutation(self):
        original = b'server:\r\nlocal-data: "other.home.arpa. A 192.168.1.3"\n'
        self.path.write_bytes(original)
        receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"], "dns-config-mixed-newlines")
        self.assertEqual(self.path.read_bytes(), original)

    def test_refuses_symlink_nonregular_and_malformed_same_name(self):
        link = self.root / "link.conf"
        link.symlink_to(self.path)
        self.assertFalse(dns.dispatch({"action": "status"}, config_path=link, checkconf=lambda p: (True, ""))["ok"])
        directory = self.root / "directory"
        directory.mkdir()
        self.assertFalse(dns.dispatch({"action": "status"}, config_path=directory, checkconf=lambda p: (True, ""))["ok"])
        self.path.write_bytes(b'local-data: "app.home.arpa. AAAA ::1"\n')
        receipt = self.call({"action": "remove", "name": "app.home.arpa"})
        self.assertFalse(receipt["ok"])
        self.assertEqual(self.path.read_bytes(), b'local-data: "app.home.arpa. AAAA ::1"\n')

    def test_candidate_failure_identity_change_and_metadata_preservation(self):
        before = self.path.read_bytes()
        failed = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=lambda p: (False, "bad"))
        self.assertFalse(failed["ok"])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)
        with mock.patch.object(dns, "_identity_matches", return_value=False):
            changed = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertFalse(changed["ok"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_postinstall_failure_rolls_back_and_rollback_failure_is_explicit(self):
        before = self.path.read_bytes()
        calls = []
        def validator(path):
            calls.append(Path(path).read_bytes())
            return (len(calls) != 2, "bad-installed" if len(calls) == 2 else "")
        receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=validator)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "restored")
        self.assertEqual(self.path.read_bytes(), before)
        rollback_calls = []
        def fails_after_install(path):
            rollback_calls.append(Path(path).read_bytes())
            return (len(rollback_calls) != 2, "bad-installed" if len(rollback_calls) == 2 else "")
        with mock.patch.object(dns, "_restore", side_effect=OSError("nope")):
            receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=fails_after_install)
        self.assertEqual(receipt["rollback"], "failed")

    def test_cli_binds_json_to_default_config_only_and_never_invokes_service(self):
        launcher = STAFF / "caduceus-network-dns"
        self.assertTrue(launcher.is_file())
        self.assertTrue(launcher.stat().st_mode & stat.S_IXUSR)
        self.assertIn("caduceus_staff.network.dns", launcher.read_text())
        parser = subprocess.run([sys.executable, "-m", "caduceus_staff.network.dns", "--config", str(self.path)], input='{"action":"status"}', cwd=STAFF, text=True, capture_output=True)
        self.assertNotEqual(parser.returncode, 0)
        self.assertIn("unrecognized arguments", parser.stderr)
        source = Path(dns.__file__).read_text()
        self.assertNotIn('add_argument("--config"', source)
        self.assertNotIn("systemctl", source)
        self.assertNotIn("service ", source)


if __name__ == "__main__":
    unittest.main()
