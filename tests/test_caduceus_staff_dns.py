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
        self.assertEqual(self.path.read_bytes(), before + b'local-data: "media.home.arpa. IN A 192.168.1.20"\n')
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
            b'  local-data: "app.home.arpa. IN A 192.168.1.2"\n  include-toplevel:',
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

    def test_guarded_rollback_replaces_inode_but_restores_exact_semantics(self):
        original = self.path.read_bytes()
        try:
            os.setxattr(self.path, "user.caduceus-restore", b"original", follow_symlinks=False)
            xattrs_supported = True
        except OSError:
            xattrs_supported = False
        before = dns._snapshot(self.path)[2]
        original_fd = os.open(self.path, os.O_RDONLY)
        checks = []
        def validator(path):
            checks.append(Path(path).read_bytes())
            return (len(checks) != 2, "bad-installed" if len(checks) == 2 else "")
        try:
            receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=validator)
            after = dns._snapshot(self.path)[2]
        finally:
            os.close(original_fd)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "restored")
        self.assertNotEqual(after.identity, before.identity)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(after.posture, before.posture)
        self.assertEqual(after.digest, before.digest)
        self.assertEqual(after.xattrs, before.xattrs)
        if xattrs_supported:
            self.assertEqual(os.getxattr(self.path, "user.caduceus-restore", follow_symlinks=False), b"original")

    def test_guarded_rollback_refuses_same_inode_metadata_mutation(self):
        before = self.path.read_bytes()
        calls = []
        def validator(path):
            calls.append(Path(path).read_bytes())
            if len(calls) == 2:
                os.chmod(self.path, 0o600)
                return False, "bad-installed"
            return True, ""
        receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=validator)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "refused-identity-content-metadata-changed")
        self.assertEqual(self.path.read_bytes(), before + b'local-data: "app.home.arpa. IN A 192.168.1.2"\n')
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

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
        self.assertEqual(receipt["rollback"], "refused-identity-content-metadata-changed")
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
        with mock.patch.object(dns, "_snapshot_is_current", return_value=False):
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
        legacy_source = source.split("# Managed drop-in lineage carried from sbin 0851389", 1)[0]
        self.assertNotIn('add_argument("--config"', legacy_source)
        self.assertNotIn("systemctl", legacy_source)
        self.assertNotIn("service ", legacy_source)

    def test_accepted_unindented_in_a_grammar_status_replace_remove_and_insertion(self):
        original = (
            b"server:\n"
            b'local-zone: "home.arpa." static\n'
            b'local-data: "git.home.arpa. IN A 192.168.123.1"\n'
            b'include-toplevel: "/etc/unbound/local.conf"\n'
            b"forward-zone:\n  name: \".\"\n"
        )
        self.path.write_bytes(original)
        status = self.call({"action": "status"})
        self.assertEqual(status["records"], [{"name": "git.home.arpa.", "address": "192.168.123.1"}])
        replaced = self.call({"action": "ensure-local-data", "name": "git.home.arpa", "address": "192.168.123.2"})
        self.assertTrue(replaced["ok"])
        expected = original.replace(b"192.168.123.1", b"192.168.123.2")
        self.assertEqual(self.path.read_bytes(), expected)
        self.assertIn(b'local-data: "git.home.arpa. IN A 192.168.123.2"', self.path.read_bytes())
        removed = self.call({"action": "remove", "name": "git.home.arpa"})
        self.assertTrue(removed["ok"])
        expected = expected.replace(b'local-data: "git.home.arpa. IN A 192.168.123.2"\n', b"")
        self.assertEqual(self.path.read_bytes(), expected)
        inserted = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.123.3"})
        self.assertTrue(inserted["ok"])
        final = self.path.read_bytes()
        self.assertIn(b'local-data: "app.home.arpa. IN A 192.168.123.3"\ninclude-toplevel:', final)
        self.assertEqual(final.split(b"forward-zone:")[1], original.split(b"forward-zone:")[1])

    def test_same_inode_content_change_at_install_seam_is_refused_without_clobber(self):
        foreign = b"server:\n# foreign same inode\n"
        real_current = dns._snapshot_is_current
        calls = 0
        def change_before_replace(path, snapshot):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.path.write_bytes(foreign)
            return real_current(path, snapshot)
        with mock.patch.object(dns, "_snapshot_is_current", side_effect=change_before_replace):
            receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"], "dns-config-identity-content-metadata-changed")
        self.assertEqual(self.path.read_bytes(), foreign)

    def test_same_inode_xattr_change_at_install_seam_is_refused_without_clobber(self):
        try:
            os.setxattr(self.path, "user.caduceus-cas", b"before", follow_symlinks=False)
        except OSError as exc:
            self.skipTest(f"filesystem does not support user xattrs: {exc}")
        real_current = dns._snapshot_is_current
        calls = 0
        def change_before_replace(path, snapshot):
            nonlocal calls
            calls += 1
            if calls == 2:
                os.setxattr(self.path, "user.caduceus-cas", b"foreign", follow_symlinks=False)
            return real_current(path, snapshot)
        with mock.patch.object(dns, "_snapshot_is_current", side_effect=change_before_replace):
            receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["error"], "dns-config-identity-content-metadata-changed")
        self.assertEqual(os.getxattr(self.path, "user.caduceus-cas", follow_symlinks=False), b"foreign")

    def test_same_inode_content_change_after_install_refuses_guarded_rollback(self):
        foreign = b"server:\n# same inode foreign after install\n"
        calls = []
        def validator(path):
            calls.append(Path(path).read_bytes())
            if len(calls) == 2:
                self.path.write_bytes(foreign)
                return False, "bad-installed"
            return True, ""
        receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=validator)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "refused-identity-content-metadata-changed")
        self.assertEqual(self.path.read_bytes(), foreign)

    def test_same_inode_xattr_change_after_install_refuses_guarded_rollback(self):
        try:
            os.setxattr(self.path, "user.caduceus-cas", b"before", follow_symlinks=False)
        except OSError as exc:
            self.skipTest(f"filesystem does not support user xattrs: {exc}")
        calls = []
        def validator(path):
            calls.append(Path(path).read_bytes())
            if len(calls) == 2:
                os.setxattr(self.path, "user.caduceus-cas", b"foreign", follow_symlinks=False)
                return False, "bad-installed"
            return True, ""
        receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=validator)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "refused-identity-content-metadata-changed")
        self.assertEqual(os.getxattr(self.path, "user.caduceus-cas", follow_symlinks=False), b"foreign")

    def test_parent_fsync_failure_restores_exact_original_snapshot(self):
        before = self.path.read_bytes()
        try:
            os.setxattr(self.path, "user.caduceus-restore", b"original", follow_symlinks=False)
            xattrs_supported = True
        except OSError:
            xattrs_supported = False
        calls = 0
        def fsync_then_recover(_path):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("parent fsync failed")
        with mock.patch.object(dns, "_fsync_parent", side_effect=fsync_then_recover):
            receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "restored")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)
        if xattrs_supported:
            self.assertEqual(os.getxattr(self.path, "user.caduceus-restore", follow_symlinks=False), b"original")

    def test_installed_snapshot_failure_after_replace_enters_guarded_rollback(self):
        before = self.path.read_bytes()
        real_snapshot = dns._snapshot
        calls = 0
        def fail_installed_snapshot(path):
            nonlocal calls
            calls += 1
            if calls == 5:
                raise OSError("installed stat failed")
            return real_snapshot(path)
        with mock.patch.object(dns, "_snapshot", side_effect=fail_installed_snapshot):
            receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertFalse(receipt["ok"])
        self.assertIn(receipt["rollback"], {"restored", "refused-identity-content-metadata-changed", "failed"})
        if receipt["rollback"] == "restored":
            self.assertEqual(self.path.read_bytes(), before)

    def test_post_install_validator_false_and_exception_both_roll_back(self):
        before = self.path.read_bytes()
        false_calls = []
        def false_validator(path):
            false_calls.append(Path(path).read_bytes())
            return (len(false_calls) != 2, "bad-installed" if len(false_calls) == 2 else "")
        false_receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=false_validator)
        self.assertFalse(false_receipt["ok"])
        self.assertEqual(false_receipt["rollback"], "restored")
        self.assertEqual(self.path.read_bytes(), before)
        exception_calls = []
        def exception_validator(path):
            exception_calls.append(Path(path).read_bytes())
            if len(exception_calls) == 2:
                raise RuntimeError("validator exploded")
            return True, ""
        exception_receipt = dns.dispatch({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"}, config_path=self.path, checkconf=exception_validator)
        self.assertFalse(exception_receipt["ok"])
        self.assertEqual(exception_receipt["validation"], "installed-exception")
        self.assertEqual(exception_receipt["rollback"], "restored")
        self.assertEqual(self.path.read_bytes(), before)

    def test_rollback_refusal_after_post_replace_failure_preserves_foreign_file(self):
        foreign = b"server:\n# foreign replacement\n"
        def fsync_fail(_path):
            raise OSError("parent fsync failed")
        real_restore = dns._restore
        def foreign_restore(*args):
            replacement = self.root / "foreign.conf"
            replacement.write_bytes(foreign)
            os.replace(replacement, self.path)
            return real_restore(*args)
        with mock.patch.object(dns, "_fsync_parent", side_effect=fsync_fail), mock.patch.object(dns, "_restore", side_effect=foreign_restore):
            receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "refused-identity-content-metadata-changed")
        self.assertEqual(self.path.read_bytes(), foreign)

    def test_nonstring_actions_and_bounded_malformed_cli_input_refuse_without_traceback(self):
        for action in ([], {}, None, 1):
            receipt = self.call({"action": action})
            self.assertFalse(receipt["ok"])
            self.assertEqual(receipt["error"], "dns-intent-invalid")
        module = [sys.executable, "-m", "caduceus_staff.network.dns"]
        malformed = subprocess.run(module, input=b'{bad', cwd=STAFF, capture_output=True)
        oversized = subprocess.run(module, input=b"x" * (dns.MAX_INPUT_BYTES + 1), cwd=STAFF, capture_output=True)
        for result, error in ((malformed, "dns-input-invalid"), (oversized, "dns-input-too-large")):
            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["error"], error)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_fixed_validator_is_not_environment_or_path_selectable(self):
        with mock.patch.object(dns.subprocess, "run") as run, mock.patch.dict(os.environ, {"CADUCEUS_UNBOUND_CHECKCONF": "/bin/true", "PATH": "/bin"}, clear=False):
            run.return_value = mock.Mock(returncode=0)
            self.assertEqual(dns._checkconf(self.path), (True, ""))
        self.assertEqual(run.call_args.args[0], ["/usr/sbin/unbound-checkconf", str(self.path)])
        source = Path(dns.__file__).read_text()
        self.assertNotIn("CADUCEUS_UNBOUND_CHECKCONF", source)
        self.assertNotIn('add_argument("--config"', source)

    def test_user_xattr_is_preserved_when_supported(self):
        name, value = "user.caduceus-test", b"preserve-me"
        try:
            os.setxattr(self.path, name, value, follow_symlinks=False)
        except OSError as exc:
            self.skipTest(f"filesystem does not support user xattrs: {exc}")
        receipt = self.call({"action": "ensure-local-data", "name": "app.home.arpa", "address": "192.168.1.2"})
        self.assertTrue(receipt["ok"])
        self.assertEqual(os.getxattr(self.path, name, follow_symlinks=False), value)


if __name__ == "__main__":
    unittest.main()
