import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAFF = ROOT / "data/staff-actuators"
sys.path.insert(0, str(STAFF))
from caduceus_staff.network import firewall

KEA = '''// comment containing "// string"
{ "Dhcp4": { "subnet4": [{"subnet":"192.168.50.0/24", # legal Kea comment
"option-data":[{"name":"routers","data":"192.168.50.1"}],
"reservations":[{"hw-address":"AA-BB-CC-DD-EE-01","ip-address":"192.168.50.22"},{"hw-address":"aa:bb:cc:dd:ee:02","ip-address":"192.168.50.23"}]}]}}\n'''


class FakeRunner:
    """Exact bounded command model; unknown commands fail, never blanket-pass."""
    def __init__(self, unbound):
        self.unbound = unbound
        self.live = None
        self.views = {}
        self.fail_apply = False
        self.fail_socket = False
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv == [str(firewall.NFT), "list", "table", "inet", "caduceus_child_filter"]:
            return (True, self.live, "none") if self.live is not None else (False, "", "not-found")
        if len(argv) == 3 and argv[:2] == [str(firewall.NFT), "-f"]:
            if self.fail_apply:
                self.fail_apply = False
                return False, "", "firewall-live-command-refused"
            batch = Path(argv[2]).read_text()
            self.live = None if batch.strip() == "delete table inet caduceus_child_filter" else "table inet" + batch.rsplit("table inet", 1)[1]
            return True, "", "none"
        if argv == [str(firewall.SYSTEMCTL), "reload", "unbound"]:
            self.views = firewall._parse_regions(self.unbound.read_bytes())
            return True, "", "none"
        if len(argv) == 3 and argv[:2] == [str(firewall.UNBOUND_CONTROL), "view_list_local_zones"]:
            if self.fail_socket: return False, "", "firewall-unbound-live-socket-unavailable"
            named = argv[2]
            for policy in self.views.values():
                if firewall.view_name(policy["mac"]) == named:
                    return True, ". refuse\n" + "".join(f"{site} transparent\n" for site in policy["fqdns"]), "none"
            return False, "", "firewall-unbound-live-view-missing"
        return False, "", "firewall-fake-command-unexpected"


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); root = Path(self.temp.name)
        self.unbound, self.nft, self.kea = root / "unbound.conf", root / "child.nft", root / "kea.json"
        self.unbound.write_bytes(b'server:\n  verbosity: 1\nforward-zone:\n  name: "."\n')
        self.nft.write_bytes(b"")
        self.kea.write_text(KEA)
        self.runner = FakeRunner(self.unbound)

    def tearDown(self): self.temp.cleanup()

    def call(self, intent):
        return firewall.dispatch(intent, unbound_path=self.unbound, nft_path=self.nft, kea_path=self.kea,
                                 checkconf=lambda _p: (True, ""), nft_check=lambda _p: (True, ""), runner=self.runner)

    def put(self, mac, sites, revision=None):
        return self.call({"action": "put", "mac": mac, "fqdns": sites,
                          "revision": revision or self.call({"action": "status"})["revision"]})

    def test_zero_policy_pure_status_is_available_with_revision(self):
        status = self.call({"action": "status"})
        self.assertTrue(status["ok"]); self.assertTrue(status["available"])
        self.assertEqual(status["policies"], []); self.assertRegex(status["revision"], r"^[0-9a-f]{64}$")
        self.assertEqual(status["firstMissingSignal"], "none")
        self.assertEqual(self.runner.calls, [])

    def test_first_put_receipt_and_refreshed_list_get_are_green(self):
        created = self.put("AA-BB-CC-DD-EE-01", ["Example.COM", "two.example.com."])
        self.assertTrue(created["ok"]); self.assertEqual(created["schema"], "caduceus.network.firewall.apply.v1")
        self.assertEqual(created["receipt"]["firstMissingSignal"], "none")
        self.assertTrue(created["receipt"]["nft"]["liveReadback"])
        listed = self.call({"action": "list"})
        self.assertTrue(listed["ok"]); policy = listed["policies"][0]
        self.assertEqual(set(policy), {"mac", "ip", "sites", "enabled", "revision", "receipt"})
        self.assertEqual(policy["receipt"]["mac"], policy["mac"])
        got = self.call({"action": "get", "mac": "aabbccddee01"})
        self.assertEqual(got["policy"]["receipt"]["firstMissingSignal"], "none")
        self.assertIn([str(firewall.UNBOUND_CONTROL), "view_list_local_zones", firewall.view_name(policy["mac"])], self.runner.calls)

    def test_live_nft_missing_extra_wrong_identity_and_hook_never_green(self):
        self.put("aa:bb:cc:dd:ee:01", ["a.example"])
        variants = [
            "",  # table missing
            "table inet caduceus_child_filter {\n chain forward {\n type filter hook forward priority 0; policy accept;\n }\n}\n",
            "table inet caduceus_child_filter {\n chain forward {\n type filter hook forward priority -5; policy accept;\n ether saddr aa:bb:cc:dd:ee:99 ip saddr 192.168.50.22 udp dport 53 ip daddr != 192.168.50.1 drop\n ether saddr aa:bb:cc:dd:ee:99 ip saddr 192.168.50.22 tcp dport 53 ip daddr != 192.168.50.1 drop\n }\n}\n",
            "table inet caduceus_child_filter {\n chain forward {\n type filter hook forward priority -5; policy accept;\n ether saddr aa:bb:cc:dd:ee:01 ip saddr 192.168.50.99 udp dport 53 ip daddr != 192.168.50.1 drop\n ether saddr aa:bb:cc:dd:ee:01 ip saddr 192.168.50.99 tcp dport 53 ip daddr != 192.168.50.1 drop\n }\n}\n",
            "table inet caduceus_child_filter {\n chain forward {\n type filter hook forward priority -5; policy accept;\n ether saddr aa:bb:cc:dd:ee:01 ip saddr 192.168.50.22 udp dport 53 ip daddr != 192.168.50.99 drop\n ether saddr aa:bb:cc:dd:ee:01 ip saddr 192.168.50.22 tcp dport 53 ip daddr != 192.168.50.99 drop\n }\n}\n",
        ]
        for live in variants:
            with self.subTest(live=live[:30]):
                self.runner.live = live or None
                receipt = self.call({"action": "list"})["policies"][0]["receipt"]
                self.assertNotEqual(receipt["firstMissingSignal"], "none")
                self.assertFalse(receipt["nft"]["liveReadback"])

    def test_live_unbound_root_site_extra_type_and_socket_never_green(self):
        self.put("aa:bb:cc:dd:ee:01", ["a.example"])
        original = self.runner.__call__
        outputs = ["a.example. transparent\n", ". refuse\n", ". refuse\na.example. refuse\n", ". refuse\na.example. transparent\nextra.example. transparent\n"]
        for output in outputs:
            def runner(argv, output=output):
                if len(argv) == 3 and argv[:2] == [str(firewall.UNBOUND_CONTROL), "view_list_local_zones"]:
                    return True, output, "none"
                return original(argv)
            with self.subTest(output=output):
                result = firewall.dispatch({"action": "list"}, unbound_path=self.unbound, nft_path=self.nft, kea_path=self.kea,
                                           checkconf=lambda _p:(True,""), nft_check=lambda _p:(True,""), runner=runner)
                self.assertNotEqual(result["policies"][0]["receipt"]["firstMissingSignal"], "none")
        self.runner.fail_socket = True
        self.assertNotEqual(self.call({"action": "list"})["policies"][0]["receipt"]["firstMissingSignal"], "none")

    def test_multiple_policy_receipts_are_bound_to_each_mac(self):
        first = self.put("aa:bb:cc:dd:ee:01", ["a.example"])
        self.put("aa:bb:cc:dd:ee:02", ["b.example"], first["revision"])
        policies = self.call({"action": "list"})["policies"]
        self.assertEqual([x["receipt"]["mac"] for x in policies], [x["mac"] for x in policies])
        self.assertTrue(all(x["receipt"]["bindingVerified"] for x in policies))

    def test_delete_proves_selected_identity_absent_and_remaining_policy_green(self):
        first = self.put("aa:bb:cc:dd:ee:01", ["a.example"])
        second = self.put("aa:bb:cc:dd:ee:02", ["b.example"], first["revision"])
        removed = self.call({"action": "delete", "mac": "aa:bb:cc:dd:ee:01", "revision": second["revision"]})
        self.assertTrue(removed["ok"]); self.assertEqual(removed["receipt"]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(removed["receipt"]["firstMissingSignal"], "none")
        self.assertNotIn("aa:bb:cc:dd:ee:01", self.runner.live)
        remaining = self.call({"action": "list"})["policies"]
        self.assertEqual([p["mac"] for p in remaining], ["aa:bb:cc:dd:ee:02"])
        self.assertEqual(remaining[0]["receipt"]["firstMissingSignal"], "none")

    def test_noop_requires_live_readback_and_existing_rollback_matrix(self):
        created = self.put("aa:bb:cc:dd:ee:01", ["a.example"])
        self.runner.live = None
        no_op = self.put("aa:bb:cc:dd:ee:01", ["a.example"], created["revision"])
        self.assertFalse(no_op["ok"])
        # Restore live then make nft application fail after both file installs.
        restored = firewall._parse_regions(self.unbound.read_bytes())
        for policy in restored.values(): policy["router"] = firewall._kea_bindings(self.kea)[policy["mac"]][1]
        self.runner.live = firewall._nft_bytes(restored).decode()
        before_u, before_n = self.unbound.read_bytes(), self.nft.read_bytes()
        self.runner.fail_apply = True
        failed = self.put("aa:bb:cc:dd:ee:01", ["new.example"])
        self.assertFalse(failed["ok"]); self.assertEqual(failed["rollback"], "restored")
        self.assertEqual(self.unbound.read_bytes(), before_u); self.assertEqual(self.nft.read_bytes(), before_n)

    def test_comment_kea_binding_and_cli_size_wall(self):
        self.assertEqual(firewall._kea_bindings(self.kea)["aa:bb:cc:dd:ee:01"], ("192.168.50.22", "192.168.50.1"))
        launcher = STAFF / "caduceus-network-firewall"; self.assertTrue(os.access(launcher, os.X_OK))
        p = subprocess.run([str(launcher)], cwd=STAFF, input=b"x" * (firewall.MAX_INPUT_BYTES + 1), capture_output=True)
        self.assertNotEqual(p.returncode, 0); self.assertEqual(json.loads(p.stdout)["error"], "firewall-input-too-large")


if __name__ == "__main__": unittest.main()
