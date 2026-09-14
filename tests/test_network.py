from dataclasses import asdict
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from nvg_key_material.files import Unavailable
from nvg_audit.airgap import cache_observation, observe
from nvg_audit.commands import command
from nvg_audit.config import load_config
from nvg_audit.models import Outcome
from nvg_audit.native import parse_observation, trusted_file, verify
from nvg_audit.net_worker import aggregate, guard, namespace_id, Lab
from nvg_audit.plugins.network_plugin import CASE_IDS, run_case

LOOP = {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "operstate": "UNKNOWN"}
DOWN = {"ifname": "nvgvpn0", "flags": ["BROADCAST"], "operstate": "DOWN"}
UP = {"ifname": "nvgvpn0", "flags": ["BROADCAST", "UP"], "operstate": "DOWN"}
BLOCKED = {"rfkilldevices": [{"id": 0, "type": "wlan", "soft": "blocked", "hard": "unblocked"}]}


class NetworkTests(unittest.TestCase):
    def test_airgap_administrative_flags_not_operstate(self):
        self.assertEqual(observe([LOOP, UP], BLOCKED).state, "mismatch")
        self.assertEqual(observe([LOOP, DOWN], BLOCKED).state, "verified")
        self.assertEqual(observe([LOOP, DOWN], {"rfkilldevices": []}).state, "verified")

    def test_airgap_indeterminate_and_known_activity_precedence(self):
        for links, radios in ((None, BLOCKED), ([], BLOCKED), ([LOOP, DOWN], None),
                              ([LOOP, DOWN], {}), ([LOOP, {"ifname": "x"}], BLOCKED),
                              ([LOOP, DOWN], {"rfkilldevices": [{"id": 0}]})):
            self.assertEqual(observe(links, radios).state, "unknown")
        self.assertEqual(observe([LOOP, UP], None).state, "mismatch")
        radios = {"rfkilldevices": [{"id": 0, "type": "wlan", "soft": "unblocked", "hard": "unblocked"}]}
        self.assertEqual(observe(None, radios).state, "mismatch")

    def test_airgap_cache_invalidation_and_operational_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cache"
            for state, operation_ok, expected in (("verified", True, True), ("verified", False, False),
                                                   ("mismatch", True, False), ("unknown", True, False)):
                path.write_text("stale")
                self.assertEqual(cache_observation(path, Outcome(state, "test"), operation_ok), expected)
                self.assertEqual(path.exists(), expected)
            with patch("nvg_audit.airgap.os.replace", side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    cache_observation(path, Outcome("verified", "test"))
            self.assertFalse(path.exists())

    def test_guard_before_any_network_mutation(self):
        with self.assertRaises(Unavailable):
            guard(namespace_id())
        with patch("nvg_audit.net_worker.checked") as commands:
            with self.assertRaises(Unavailable):
                Lab({}, namespace_id(), namespace_id("user"))
            commands.assert_not_called()
        with self.assertRaises(Unavailable):
            guard(0, 0)

    def test_block_requires_verdict_and_positive_controls(self):
        for response, packets, expected in (("peer", 0, "mismatch"), (None, 0, "unknown"),
                                             (None, 1, "verified")):
            lab = MagicMock()
            lab.counter.side_effect = [1, 0, packets]
            lab.exchange.return_value = response
            result = Lab.block(lab, "198.18.0.3", 18080, "udp", "tor")
            self.assertEqual(result["state"], expected)
            self.assertEqual(lab.control.call_count, 3)
            lab.health.assert_called_once()

    def test_no_conntrack_baseline_cannot_pass(self):
        lab = MagicMock()
        lab.counter.return_value = 0
        with self.assertRaises(Unavailable):
            Lab.block(lab, "198.18.0.3", 18080, "tcp", "tor")

    def test_missing_tools_permission_timeout_and_invalid_worker(self):
        config = load_config()
        with patch("nvg_audit.plugins.network_plugin.shutil.which", return_value=None):
            self.assertEqual(run_case(CASE_IDS[0], config).state, "unknown")
        with patch("nvg_audit.plugins.network_plugin.shutil.which", return_value="/usr/bin/tool"):
            for returned in ((1, ""), (0, "not json"), (0, '{"state":"pass"}')):
                with patch("nvg_audit.plugins.network_plugin.command", return_value=returned):
                    self.assertEqual(run_case(CASE_IDS[0], config).state, "unknown")
            with patch("nvg_audit.plugins.network_plugin.command", side_effect=Unavailable("timeout")):
                self.assertEqual(run_case(CASE_IDS[0], config).state, "unknown")

    def test_worker_three_state_mapping(self):
        config = load_config()
        with patch("nvg_audit.plugins.network_plugin.shutil.which", return_value="/usr/bin/tool"):
            for state in ("verified", "mismatch", "unknown"):
                raw = json.dumps(asdict(Outcome(state, "worker result", {"namespace_real": True})))
                with patch("nvg_audit.plugins.network_plugin.command", return_value=(0, raw)):
                    self.assertEqual(run_case(CASE_IDS[0], config).state, state)

    def test_aggregation_never_hides_unknown(self):
        self.assertEqual(aggregate([]).state, "unknown")
        self.assertEqual(aggregate([{"state": "pass"}]).state, "unknown")
        self.assertEqual(aggregate([{"state": "verified"}, {"state": "unknown"}]).state, "unknown")
        self.assertEqual(aggregate([{"state": "mismatch"}, {"state": "unknown"}]).state, "mismatch")

    def test_native_contract_freshness_exit_and_domain(self):
        from datetime import datetime, timezone
        now = time.time()
        doc = {"schema_version": 1, "observed_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
               "verification": {"requested": "tor", "state": "verified"},
               "firewall": {"state": "verified", "mode": "tor"}}
        self.assertEqual(parse_observation(json.dumps(doc), 0, "tor", now, now).state, "verified")
        self.assertEqual(parse_observation(json.dumps(doc), 2, "tor", now, now).state, "unknown")
        self.assertEqual(parse_observation(json.dumps(doc), 0, "tor", now + 10, now + 10).state, "unknown")
        doc["firewall"]["mode"] = "base"
        self.assertEqual(parse_observation(json.dumps(doc), 0, "tor", now, now).state, "unknown")
        doc["verification"]["state"] = "mismatch"
        self.assertEqual(parse_observation(json.dumps(doc), 1, "tor", now, now).state, "mismatch")
        doc["verification"]["state"] = "unknown"
        self.assertEqual(parse_observation(json.dumps(doc), 2, "tor", now, now).state, "unknown")

    def test_native_trust_before_execution(self):
        with patch("nvg_audit.native.trusted_file", side_effect=Unavailable("untrusted")), \
                patch("nvg_audit.native.command") as run:
            self.assertEqual(verify(load_config(), "tor").state, "unknown")
            run.assert_not_called()
        for mode, uid in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o666, 0), (stat.S_IFREG | 0o644, 1000)):
            with patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)):
                with self.assertRaises(Unavailable):
                    trusted_file("/usr/lib/test")

    def test_command_capture_timeout_output_limit_and_stderr(self):
        import sys
        code, raw = command([sys.executable, "-c", "import sys; print('ok'); print('private', file=sys.stderr)"])
        self.assertEqual((code, raw), (0, "ok\n"))
        with self.assertRaises(Unavailable):
            command([sys.executable, "-c", "import time; time.sleep(20)"], timeout=0.05)
        with self.assertRaises(Unavailable):
            command([sys.executable, "-c", "print('x'*10000)"], limit=100)
