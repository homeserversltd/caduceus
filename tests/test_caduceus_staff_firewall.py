import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
STAFF = ROOT / "data/staff-actuators"
sys.path.insert(0, str(STAFF))
from caduceus_staff.network import firewall

KEA = '''// lawful comment with "// string"
{ "Dhcp4": { "subnet4": [{"subnet":"192.168.50.0/24", # comment
"option-data":[{"name":"routers","data":"192.168.50.1"}],
"reservations":[{"hw-address":"AA-BB-CC-DD-EE-01","ip-address":"192.168.50.22"},{"hw-address":"aa:bb:cc:dd:ee:02","ip-address":"192.168.50.23"}]}]}}\n'''

class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.unbound = self.root / "unbound.conf"; self.nft = self.root / "child.nft"; self.kea = self.root / "kea.json"
        self.unbound.write_bytes(b'server:\n  verbosity: 1\nforward-zone:\n  name: "."\n')
        self.nft.write_bytes(b'# inert initial seed\n'); self.kea.write_text(KEA)
    def tearDown(self): self.temp.cleanup()
    def runner(self, argv):
        if argv[:2] == [str(firewall.NFT), "list"]: return True, "table inet caduceus_child_filter {}", "none"
        return True, "", "none"
    def call(self, intent, **kw):
        return firewall.dispatch(intent, unbound_path=self.unbound, nft_path=self.nft, kea_path=self.kea, checkconf=lambda p:(True,""), nft_check=lambda p:(True,""), runner=self.runner, **kw)
    def test_comments_strings_and_exact_binding_router(self):
        self.assertEqual(firewall._kea_bindings(self.kea)["aa:bb:cc:dd:ee:01"], ("192.168.50.22", "192.168.50.1"))
        receipt = self.call({"action":"put","mac":"AABBCCDDEE01","fqdns":["Example.COM", "two.example.com."]})
        self.assertTrue(receipt["ok"]); self.assertIn(b"192.168.50.22/32", self.unbound.read_bytes())
        nft = self.nft.read_text(); self.assertIn("table inet caduceus_child_filter", nft); self.assertIn("192.168.50.1", nft); self.assertNotIn("192.168.123.1", nft)
    def test_multiple_roundtrip_get_list_update_delete(self):
        a = self.call({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["a.example"]}); self.assertTrue(a["ok"])
        b = self.call({"action":"put","mac":"aa:bb:cc:dd:ee:02","fqdns":["b.example"]}); self.assertTrue(b["ok"])
        listed = self.call({"action":"list"}); self.assertEqual(len(listed["policies"]), 2)
        got = self.call({"action":"get","mac":"aa:bb:cc:dd:ee:02"}); self.assertEqual(got["policy"]["fqdns"], ["b.example."])
        update = self.call({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["new.example"],"revision":listed["revision"]}); self.assertTrue(update["ok"])
        delete = self.call({"action":"delete","mac":"aa:bb:cc:dd:ee:02","revision":update["revision"]}); self.assertTrue(delete["ok"])
    def test_bootstrap_preserves_unrelated_bytes_and_empty_available(self):
        before = self.unbound.read_bytes(); status = self.call({"action":"status"})
        self.assertTrue(status["ok"]); self.assertEqual(status["policies"], [])
        self.call({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["a.example"]})
        after = self.unbound.read_bytes(); self.assertIn(firewall.BEGIN_ACCESS, after); self.assertEqual(after.replace(firewall._render_access({"aa:bb:cc:dd:ee:01":{"ip":"192.168.50.22","fqdns":["a.example."]}}, b"\n").replace(firewall.END_ACCESS+b"\n",b""),b"").split(b"forward-zone:")[1], before.split(b"forward-zone:")[1])
    def test_duplicate_foreign_and_mismatch_refuse(self):
        self.unbound.write_bytes(b"server:\n" + firewall.BEGIN_ACCESS+b"\n"+firewall.END_ACCESS+b"\n"+firewall.BEGIN_ACCESS+b"\n"+firewall.END_ACCESS+b"\n")
        r=self.call({"action":"status"}); self.assertFalse(r["ok"]); self.assertEqual(r["error"],"firewall-unbound-markers-duplicate")
        self.unbound.write_bytes(b"server:\n"+firewall.BEGIN_ACCESS+b"\n evil: yes\n"+firewall.END_ACCESS+b"\n"+firewall.BEGIN_VIEWS+b"\n"+firewall.END_VIEWS+b"\n")
        r=self.call({"action":"status"}); self.assertFalse(r["ok"])
    def test_revision_extra_bounds_mac_fqdn(self):
        bad = self.call({"action":"put","mac":"bad","fqdns":["a.example"]}); self.assertFalse(bad["ok"])
        bad = self.call({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["a.example"],"evil":1}); self.assertFalse(bad["ok"])
        bad = self.call({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["x.example"]*65}); self.assertFalse(bad["ok"])
        created = self.call({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["a.example"]}); self.assertTrue(created["ok"])
        conflict = self.call({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["a.example"]}); self.assertFalse(conflict["ok"])
    def test_live_apply_failure_rolls_back_two_files(self):
        before_u, before_n = self.unbound.read_bytes(), self.nft.read_bytes()
        attempts = []
        def fail(argv):
            if argv[:2] == [str(firewall.NFT), "-f"]:
                attempts.append(argv)
                if len(attempts) == 1: return False, "", "nft-failed"
            return True,"","none"
        r = firewall.dispatch({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["a.example"]}, unbound_path=self.unbound,nft_path=self.nft,kea_path=self.kea,checkconf=lambda p:(True,""),nft_check=lambda p:(True,""),runner=fail)
        self.assertFalse(r["ok"]); self.assertEqual(r["rollback"],"restored"); self.assertEqual(self.unbound.read_bytes(),before_u); self.assertEqual(self.nft.read_bytes(),before_n)
    def test_foreign_replacement_refuses_rollback(self):
        foreign=b"foreign\n"; calls=[]
        def check(p):
            calls.append(Path(p).read_bytes())
            if len(calls)==2: self.unbound.write_bytes(foreign); return False,"bad"
            return True,""
        r=firewall.dispatch({"action":"put","mac":"aa:bb:cc:dd:ee:01","fqdns":["a.example"]},unbound_path=self.unbound,nft_path=self.nft,kea_path=self.kea,checkconf=check,nft_check=lambda p:(True,""),runner=self.runner)
        self.assertFalse(r["ok"]); self.assertEqual(self.unbound.read_bytes(),foreign)
    def test_cli_launcher_and_size_wall(self):
        launcher=STAFF/"caduceus-network-firewall"; self.assertTrue(os.access(launcher,os.X_OK))
        p=subprocess.run([str(launcher)],cwd=STAFF,input=b"x"*(firewall.MAX_INPUT_BYTES+1),capture_output=True)
        self.assertNotEqual(p.returncode,0); self.assertEqual(json.loads(p.stdout)["error"],"firewall-input-too-large")
        p=subprocess.run([sys.executable,"-m","caduceus_staff.network.firewall"],cwd=STAFF,input=b"x"*(firewall.MAX_INPUT_BYTES+1),capture_output=True)
        self.assertNotEqual(p.returncode,0); self.assertEqual(json.loads(p.stdout)["error"],"firewall-input-too-large")

if __name__ == "__main__": unittest.main()
