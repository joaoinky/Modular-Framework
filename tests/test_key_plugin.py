import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nvg_audit.config import load_config
from nvg_audit.engine import execute
from nvg_audit.plugins import key_exposure_plugin as plugin
from nvg_key_material.files import Read, Unavailable

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "packages/nvg-key-material/tests/public_key_vectors.json").read_text())
NIP49 = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p"


class KeyPluginTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "chave.ncryptsec"
        self.path.write_text(NIP49 + "\n")
        self.path.chmod(0o600)
        self.config = load_config()
        self.config["key_exposure"].update(enabled=True, key_path=str(self.path), expected_uid=os.getuid())

    def test_valid_envelope_and_exact_permissions(self):
        report = execute(self.config, modules={"key_exposure": plugin})
        self.assertEqual(report["summary"], {"verified": 2, "mismatch": 0, "unknown": 0})
        self.assertNotIn(NIP49[:20], json.dumps(report))

    def test_plaintext_public_vectors_and_no_secret_or_hash(self):
        for value in VECTORS.values():
            self.path.write_text(value)
            report = execute(self.config, modules={"key_exposure": plugin})
            self.assertEqual(report["results"][0]["state"], "mismatch")
            text = json.dumps(report)
            self.assertNotIn(value[:10], text)
            self.assertNotIn(hashlib.sha256(value.encode()).hexdigest(), text)

    def test_mode_and_owner_regressions(self):
        for mode in (0o644, 0o400, 0o1600):
            self.path.chmod(mode)
            self.assertEqual(plugin.permissions(self.config).state, "mismatch")
        self.path.chmod(0o600)
        self.config["key_exposure"]["expected_uid"] += 1
        self.assertEqual(plugin.permissions(self.config).state, "mismatch")

    def test_declared_missing_file_is_mismatch(self):
        self.path.unlink()
        report = execute(self.config, modules={"key_exposure": plugin})
        self.assertEqual(report["summary"], {"verified": 0, "mismatch": 2, "unknown": 0})
        self.config["key_exposure"]["key_path"] = str(self.path / "missing-parent" / "key")
        self.assertEqual(plugin.envelope(self.config).state, "mismatch")
        self.assertEqual(plugin.permissions(self.config).state, "mismatch")

    def test_symlink_partial_and_disabled_unknown(self):
        self.path.unlink()
        self.path.symlink_to("missing")
        self.assertEqual(plugin.envelope(self.config).state, "unknown")
        self.assertEqual(plugin.permissions(self.config).state, "unknown")
        self.path.unlink()
        self.path.write_text(NIP49)
        self.config["key_exposure"]["limits"] = {"max_file_bytes": 4}
        self.assertEqual(plugin.envelope(self.config).state, "unknown")
        self.config["key_exposure"]["enabled"] = False
        with patch.object(plugin.Budget, "read", side_effect=AssertionError("must not read")):
            self.assertEqual(plugin.envelope(self.config).state, "unknown")

    def test_unreadable_and_failed_queries_unknown(self):
        with patch.object(plugin.Budget, "read", side_effect=Unavailable("private")):
            self.assertEqual(plugin.envelope(self.config).state, "unknown")
        with patch.object(plugin.os, "lstat", side_effect=PermissionError("private")):
            self.assertEqual(plugin.envelope(self.config).state, "unknown")
            self.assertEqual(plugin.permissions(self.config).state, "unknown")
        with patch.object(plugin.Budget, "read", return_value=Read(NIP49.encode(), True, 0o600, os.getuid())):
            self.assertEqual(plugin.envelope(self.config).state, "unknown")

    def test_detector_timeout_and_disappearance_during_read_unknown(self):
        with patch.object(plugin, "detect", return_value=({}, {}, True)):
            self.assertEqual(plugin.envelope(self.config).state, "unknown")
        with patch.object(plugin.Budget, "read", side_effect=FileNotFoundError()):
            self.assertEqual(plugin.envelope(self.config).state, "unknown")

    def test_disabled_missing_path_is_not_inspected(self):
        self.path.unlink()
        self.config["key_exposure"]["enabled"] = False
        with patch.object(plugin.os, "lstat", side_effect=AssertionError("must not inspect")):
            self.assertEqual(plugin.envelope(self.config).state, "unknown")
            self.assertEqual(plugin.permissions(self.config).state, "unknown")

    def test_invalid_envelope_mismatch_and_candidates_unknown(self):
        for text in ("nothing", "ncryptsec1invalid", NIP49[:-1] + "q"):
            self.path.write_text(text)
            self.assertEqual(plugin.envelope(self.config).state, "mismatch")
        for text in ("nsec1qqqqqqqqqqqqqqqq", "nvgs2-public-test"):
            self.path.write_text(text)
            self.assertEqual(plugin.envelope(self.config).state, "unknown")

    def test_secret_in_filename_omitted(self):
        renamed = self.path.with_name(VECTORS["nsec"])
        self.path.rename(renamed)
        self.config["key_exposure"]["key_path"] = str(renamed)
        report = execute(self.config, modules={"key_exposure": plugin})
        self.assertNotIn(VECTORS["nsec"][:10], json.dumps(report))
