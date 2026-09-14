import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from nvg_key_material import detect, safe_location, valid_mnemonic, valid_nsec, valid_wif, wordlist
from nvg_key_material.encrypted import ncryptsec_format
from nvg_key_material.files import Budget, Limits, Unavailable, inspect_files, read_regular, select_files

VECTORS = json.loads(Path(__file__).with_name("public_key_vectors.json").read_text())
# Public NIP-49 decryption vector, not a user's key. No decryption is performed.
NIP49 = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p"


class MaterialTests(unittest.TestCase):
    def test_public_vectors_and_corruption(self):
        self.assertTrue(valid_nsec(VECTORS["nsec"]))
        self.assertTrue(valid_wif(VECTORS["wif"]))
        self.assertTrue(valid_mnemonic(VECTORS["bip39"].split(), wordlist()))
        self.assertFalse(valid_nsec(VECTORS["nsec"][:-1] + "q"))
        self.assertFalse(valid_wif(VECTORS["wif"][:-1] + "1"))
        self.assertFalse(valid_mnemonic(["abandon"] * 12, wordlist()))
        self.assertEqual(len(wordlist()), 2048)

    def test_counts_and_confidentiality(self):
        content = "\nNONWORDSEPARATOR\n".join(VECTORS.values())
        counts, candidates, partial = detect(content, wordlist())
        self.assertEqual(counts, {"nsec": 1, "wif": 1, "bip39": 1, "bunker_credential": 0})
        self.assertFalse(any(candidates.values()) or partial)
        rendered = json.dumps((counts, candidates, partial))
        for token in VECTORS.values():
            self.assertNotIn(token[:10], rendered)
            self.assertNotIn(hashlib.sha256(token.encode()).hexdigest(), rendered)

    def test_nsec_case_and_bounds(self):
        self.assertTrue(valid_nsec(VECTORS["nsec"].upper()))
        self.assertFalse(valid_nsec("N" + VECTORS["nsec"][1:]))
        self.assertFalse(valid_nsec("nsec1qqqqqqqqqqqqqqqq"))

    def test_no_mnemonic_reconstruction(self):
        phrase = VECTORS["bip39"].replace(" ", " NONWORDSEPARATOR ")
        self.assertEqual(detect(phrase, wordlist())[0]["bip39"], 0)
        self.assertEqual(detect(VECTORS["bip39"].replace(" ", ","), wordlist())[0]["bip39"], 0)

    def test_deadline_and_candidates(self):
        self.assertTrue(detect(VECTORS["nsec"], wordlist(), deadline=0)[2])
        self.assertEqual(detect("nsec1qqqqqqqqqqqq", wordlist())[1]["nsec"], 1)

    def test_bunker_and_shamir_preserve_scanner_semantics(self):
        credential = "bunker://" + "a" * 64 + "?secret=public-test"
        counts, candidates, _ = detect(credential + " nvgs1-public-test nvgs2-public-test", wordlist())
        self.assertEqual(counts["bunker_credential"], 1)
        self.assertEqual(candidates["shamir_share"], 2)
        self.assertEqual(detect("bunker://invalid?secret=x", wordlist())[1]["bunker"], 1)
        self.assertEqual(detect("nvgs1withoutdash", wordlist())[1]["shamir_share"], 0)

    def test_sensitive_labels_omitted(self):
        for value in (*VECTORS.values(), "bunker://public", "nvgs2-public"):
            self.assertNotEqual(safe_location("/tmp/" + value), "/tmp/" + value)

    def test_nip49_structure_not_plaintext(self):
        self.assertEqual(ncryptsec_format(NIP49), "valid")
        self.assertEqual(ncryptsec_format(NIP49.upper()), "valid")
        self.assertEqual(ncryptsec_format(NIP49[:-1] + "q"), "invalid")
        self.assertEqual(ncryptsec_format("ncryptsec-not-a-key"), "invalid")
        self.assertFalse(any(detect(NIP49, wordlist())[0].values()))

    def test_regular_read_rejects_fifo_symlink_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "file"
            path.write_bytes(b"public data")
            link, fifo = Path(folder) / "link", Path(folder) / "fifo"
            link.symlink_to(path)
            os.mkfifo(fifo)
            for item in (link, fifo, folder):
                with self.assertRaises(Unavailable):
                    read_regular(item, 20)
            read = read_regular(path, 3)
            self.assertEqual(read.data, b"pub")
            self.assertTrue(read.partial)
            self.assertNotIn("pub", repr(read))

    def test_budget_bytes_files_time(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "file"
            path.write_bytes(b"abcdefghij")
            budget = Budget(Limits(max_files=1))
            budget.read(path)
            with self.assertRaises(Unavailable):
                budget.read(path)
            budget = Budget(Limits(max_total_bytes=3))
            self.assertTrue(budget.read(path).partial)
            with self.assertRaises(Unavailable):
                budget.read(path)
            budget = Budget()
            budget.deadline = 0
            with self.assertRaises(Unavailable):
                budget.read(path)

    def test_selection_bounds_and_no_recursion(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in ("a.log", "b.log", "c.log"):
                Path(folder, name).touch()
            selected, partial = select_files(folder + "/*.log", 2)
            self.assertEqual(len(selected), 2)
            self.assertTrue(partial)
            for pattern in (folder + "/**", folder + "/*/file", "relative"):
                with self.assertRaises(Unavailable):
                    select_files(pattern)

    def test_inspection_metadata_only_and_partial_not_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "file"
            path.write_text(VECTORS["nsec"])
            rows = list(inspect_files([str(path)]))
            self.assertEqual(rows[0]["counts"]["nsec"], 1)
            self.assertNotIn(VECTORS["nsec"][:10], json.dumps(rows))
            rows = list(inspect_files([str(path)], Limits(max_file_bytes=4)))
            self.assertFalse(rows[0]["complete"])
            self.assertFalse(list(inspect_files([folder + "/missing"]))[0]["complete"])

    def test_limits_have_hard_ceilings(self):
        for kwargs in ({"max_files": 65}, {"max_seconds": float("nan")}, {"max_file_bytes": True},
                       {"max_total_bytes": 8388609}, {"max_directory_entries": 0}):
            with self.assertRaises(ValueError):
                Limits(**kwargs)
