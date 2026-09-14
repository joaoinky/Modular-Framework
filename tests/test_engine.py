from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from nvg_audit.__main__ import main
from nvg_audit.config import load_config
from nvg_audit.engine import discover, execute, exit_code
from nvg_audit.models import Case, Outcome


def module(*cases):
    return SimpleNamespace(cases=lambda config: iter(cases))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.config = load_config()

    def test_mock_plugins_all_three_states(self):
        plugin = module(*(Case(state, lambda cfg, state=state: Outcome(state, "test"))
                          for state in ("verified", "mismatch", "unknown")))
        report = execute(self.config, modules={"mock": plugin})
        self.assertEqual(report["summary"], {"verified": 1, "mismatch": 1, "unknown": 1})
        self.assertEqual(exit_code(report), 1)
        self.assertEqual(report["plugins_executed"], ["mock"])
        self.assertEqual(report["schema_version"], 1)
        json.dumps(report, allow_nan=False)

    def test_timeout_is_unknown_and_next_case_runs(self):
        self.config["execution"]["case_timeouts"]["slow"] = 0.05
        plugin = module(Case("slow", lambda cfg: time.sleep(10)),
                        Case("next", lambda cfg: Outcome("verified", "next case ran")))
        started = time.monotonic()
        report = execute(self.config, modules={"mock": plugin})
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual([r["state"] for r in report["results"]], ["unknown", "verified"])
        self.assertEqual(exit_code(report), 3)

    def test_error_does_not_copy_secret_or_stop_others(self):
        def broken(cfg):
            print("nsec1secret-not-to-log")
            raise RuntimeError("bunker://secret-not-to-log")
        plugin = module(Case("broken", broken), Case("ok", lambda cfg: Outcome("verified", "ok")))
        report = execute(self.config, modules={"mock": plugin})
        self.assertEqual(report["summary"]["unknown"], 1)
        self.assertEqual(report["summary"]["verified"], 1)
        self.assertNotIn("secret-not-to-log", json.dumps(report))

    def test_invalid_results_never_verified(self):
        for value in (None, Outcome("pass", "binary"), Outcome("verified", ""),
                      Outcome("verified", "bad", {"x": float("nan")}),
                      Outcome("verified", "bad", {"x": object()}),
                      Outcome("verified", "x" * 300000)):
            with self.subTest(value=type(value)):
                report = execute(self.config, modules={"mock": module(Case("bad", lambda cfg: value))})
                self.assertEqual(report["summary"]["unknown"], 1)

    def test_empty_duplicate_reserved_and_partial_enumeration(self):
        ok = Case("ok", lambda cfg: Outcome("verified", "ok"))
        for plugin in (module(), module(ok, ok), module(Case("engine_reserved", ok.run))):
            self.assertEqual(execute(self.config, modules={"mock": plugin})["summary"]["unknown"], 1)
        def incomplete(cfg):
            yield ok
            raise ValueError("sensitive")
        report = execute(self.config, modules={"mock": SimpleNamespace(cases=incomplete)})
        self.assertEqual(report["summary"], {"verified": 1, "mismatch": 0, "unknown": 1})

    def test_import_discovery_and_failures_with_mock_package(self):
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "mock_discovery"
            package.mkdir()
            (package / "__init__.py").touch()
            (package / "ok_plugin.py").write_text("def cases(config): return []\n")
            (package / "bad_plugin.py").write_text("raise ValueError('secret')\n")
            (package / "ignored.py").write_text("raise AssertionError()\n")
            sys.path.insert(0, folder)
            try:
                modules, errors = discover("mock_discovery")
                self.assertEqual(list(modules), ["ok"])
                self.assertEqual(list(errors), ["bad"])
                report = execute(self.config, modules=modules, errors=errors)
                self.assertEqual(report["summary"]["unknown"], 2)
                self.assertNotIn("secret", json.dumps(report))
            finally:
                sys.path.remove(folder)

    def test_redaction_in_reason_evidence_and_target(self):
        self.config["target"]["description"] = "bunker://sensitive-location"
        plugin = module(Case("redact", lambda cfg: Outcome("mismatch", "nvgs2-sensitive-reason",
                                                          {"path": "nsec1sensitive", "nested": ["ncryptsec1sensitive"]})))
        self.assertNotIn("sensitive", json.dumps(execute(self.config, modules={"mock": plugin})))

    def test_output_mode_no_overwrite_and_exit_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "report.json"
            args = ["--plugin", "key_exposure", "--output", str(target)]
            self.assertEqual(main(args), 3)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            original = target.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(target.read_bytes(), original)

    def test_cli_list_and_unknown_selection(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--list-plugins"]), 0)
        self.assertEqual(json.loads(output.getvalue())["plugins"], ["key_exposure", "network"])
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--plugin", "nonexistent"]), 2)

    def test_missing_or_special_config_is_usage_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as folder:
            fifo = Path(folder) / "config-fifo"
            os.mkfifo(fifo)
            for path in (fifo, Path(folder) / "missing"):
                error = io.StringIO()
                with redirect_stderr(error):
                    self.assertEqual(main(["--target-config", str(path)]), 2)
                self.assertNotIn("Traceback", error.getvalue())
                self.assertNotIn(str(path), error.getvalue())

    def test_configuration_rejects_typos_remote_and_invalid_timeouts(self):
        bad = [{"network": {"mode": "ssh"}}, {"network": {"library": "relative"}},
               {"execution": {"timeout_seconds": True}}, {"execution": {"timeout_seconds": 0}},
               {"execution": {"case_timeouts": {"x": float("nan")}}},
               {"key_exposure": {"enabled": True}}, {"unknown": True}]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            for value in bad:
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_config(path)
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ValueError):
                load_config(path)

    def test_child_descendants_are_terminated(self):
        import subprocess
        def slow(cfg):
            subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
            time.sleep(20)
        self.config["execution"]["timeout_seconds"] = 0.05
        started = time.monotonic()
        report = execute(self.config, modules={"mock": module(Case("slow", slow))})
        self.assertEqual(report["summary"]["unknown"], 1)
        self.assertLess(time.monotonic() - started, 2)
