"""Optional checkout comparison; the original is loaded in a separate process."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from nvg_key_material import patterns


VECTORS_PATH = Path(__file__).with_name("public_key_vectors.json")
SCANNER = Path(os.environ.get("NVG_SCANNER_CHECKOUT",
                             str(Path(__file__).resolve().parents[4] / "Hardening-scanner")))


class ScannerEquivalenceTests(unittest.TestCase):
    def test_public_vectors_match_extraction_baseline(self):
        self.assertEqual(hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest(),
                         "c6819a85c5d1cbaad27be8ffce6988c032dd24e86a2e375ab20ee94f523883fc")

    def test_original_and_extracted_field_equivalence(self):
        if not (SCANNER / "src/nvg_scanner/key_patterns.py").is_file():
            if "NVG_SCANNER_CHECKOUT" in os.environ:
                self.fail("Explicit scanner checkout is unavailable")
            self.skipTest("Original scanner unavailable; set NVG_SCANNER_CHECKOUT")
        vectors = json.loads(VECTORS_PATH.read_text())
        self.assertEqual(vectors, json.loads((SCANNER / "tests/public_key_vectors.json").read_text()))
        corpus = [*vectors.values(), "\nNONWORDSEPARATOR\n".join(vectors.values()),
                  "", "ordinary public text", vectors["nsec"].upper(),
                  "N" + vectors["nsec"][1:], vectors["nsec"][:-1] + "q",
                  vectors["wif"][:-1] + "1", " ".join(["abandon"] * 12),
                  vectors["bip39"].replace(" ", ","), "nsec1qqqqqqqqqqqq",
                  "nvgs1-public-test nvgs2-public-test nvgs1withoutdash",
                  "bunker://" + "a" * 64 + "?secret=public-test",
                  "bunker://" + "a" * 64 + "?secret=&secret=x",
                  "bunker://invalid?secret=x"]
        probe = '''
import json, sys
sys.path.insert(0, sys.argv[1])
from nvg_scanner import key_patterns as p
texts = json.load(sys.stdin)
vocabulary = p.wordlist()
print(json.dumps({"wordlist": vocabulary, "rows": [
    {"detect": p.detect(t, vocabulary), "expired": p.detect(t, vocabulary, deadline=0),
     "nsec": p.valid_nsec(t), "wif": p.valid_wif(t),
     "mnemonic": p.valid_mnemonic(t.split(), vocabulary), "location": p.safe_location(t)}
    for t in texts]}))
'''
        result = subprocess.run([sys.executable, "-I", "-c", probe, str(SCANNER / "src")],
                                input=json.dumps(corpus), text=True, capture_output=True,
                                timeout=30, check=True)
        original = json.loads(result.stdout)
        vocabulary = patterns.wordlist()
        self.assertEqual(vocabulary, original["wordlist"])
        self.assertEqual(len(corpus), len(original["rows"]))
        for index, (text, expected) in enumerate(zip(corpus, original["rows"])):
            actual = {"detect": patterns.detect(text, vocabulary),
                      "expired": patterns.detect(text, vocabulary, deadline=0),
                      "nsec": patterns.valid_nsec(text), "wif": patterns.valid_wif(text),
                      "mnemonic": patterns.valid_mnemonic(text.split(), vocabulary),
                      "location": patterns.safe_location(text)}
            actual = json.loads(json.dumps(actual))
            for field in actual:
                with self.subTest(vector=index, field=field):
                    self.assertEqual(actual[field], expected[field])
