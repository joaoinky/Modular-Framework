"""Opt-in real kernel suite. When requested, missing privileges are failures."""

import os
from pathlib import Path
import tempfile
import unittest

from examples.make_regressions import write_fixture
from nvg_audit.config import load_config
from nvg_audit.engine import execute
from nvg_audit.plugins.network_plugin import CASE_IDS


@unittest.skipUnless(os.environ.get("NVG_RUN_NETNS") == "1", "Real namespace integration not requested (NVG_RUN_NETNS=1)")
class NamespaceIntegration(unittest.TestCase):
    def config(self):
        cfg = load_config()
        cfg["execution"]["case_timeouts"] = {case_id: 60 for case_id in CASE_IDS}
        return cfg

    def test_corrected_rules_all_five_cases(self):
        report = execute(self.config(), ["network"])
        self.assertEqual(len(report["results"]), 5)
        for result in report["results"]:
            with self.subTest(case=result["case_id"]):
                self.assertEqual(result["state"], "verified", result)
                self.assertTrue(result["evidence"]["namespace_real"])

    def test_old_rule_controls_must_be_mismatch_never_unknown(self):
        for regression, case_id in zip(("nvg06", "nvg07", "nvg10", "nvg11"),
                                        (CASE_IDS[0], CASE_IDS[1], CASE_IDS[3], CASE_IDS[4])):
            with self.subTest(regression=regression), tempfile.TemporaryDirectory() as folder:
                cfg = self.config()
                directory = Path(folder) / "broken"
                write_fixture(directory, regression)
                cfg["network"]["rules_dir"] = str(directory)
                # Only the selected regression case is needed for this control.
                from nvg_audit.models import Case
                from nvg_audit.plugins.network_plugin import run_case
                from functools import partial
                from types import SimpleNamespace
                plugin = SimpleNamespace(cases=lambda cfg: [Case(case_id, partial(run_case, case_id))])
                result = execute(cfg, modules={"network": plugin})["results"][0]
                self.assertEqual(result["state"], "mismatch", result)
