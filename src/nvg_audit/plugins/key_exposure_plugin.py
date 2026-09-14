import os
import stat
import time

from nvg_key_material import detect, safe_location, wordlist
from nvg_key_material.encrypted import ncryptsec_format
from nvg_key_material.files import Budget, Limits, Unavailable

from ..models import Case, Outcome


def enabled(config):
    return config["key_exposure"]["enabled"]


def envelope(config):
    if not enabled(config):
        return Outcome("unknown", "Key inspection disabled; explicit path, UID and opt-in required")
    policy = config["key_exposure"]
    evidence = {"location": safe_location(policy["key_path"])}
    try:
        budget = Budget(Limits(**policy["limits"]))
        read = budget.read(policy["key_path"])
        counts, candidates, timed_out = detect(read.data.decode("utf-8", errors="replace"),
                                                wordlist(), budget.deadline)
        evidence["counts"] = {k: v for k, v in counts.items() if v}
        evidence["candidates"] = {k: v for k, v in candidates.items() if v}
        if read.partial or timed_out or time.monotonic() >= budget.deadline:
            return Outcome("unknown", "Key file inspection incomplete or timed out", evidence)
        if any(counts.values()):
            return Outcome("mismatch", "Plaintext material found in the expected encrypted key file", evidence)
        if any(candidates.values()):
            return Outcome("unknown", "Unconfirmed plaintext or Shamir candidate; no reconstruction", evidence)
        try:
            token = read.data.decode("ascii").strip()
        except UnicodeDecodeError:
            return Outcome("mismatch", "Expected a single NIP-49 envelope", evidence)
        result = ncryptsec_format(token)
        if result == "unsupported":
            return Outcome("unknown", "Unsupported NIP-49 envelope version", evidence)
        if result == "invalid":
            return Outcome("mismatch", "NIP-49 envelope structure or checksum invalid", evidence)
        return Outcome("verified", "NIP-49 v2 envelope structure confirmed; ciphertext not authenticated", evidence)
    except (Unavailable, OSError, ValueError):
        return Outcome("unknown", "Key file or detector data unavailable", evidence)


def permissions(config):
    if not enabled(config):
        return Outcome("unknown", "Key inspection disabled; explicit path, UID and opt-in required")
    policy = config["key_exposure"]
    evidence = {"location": safe_location(policy["key_path"])}
    try:
        metadata = os.lstat(policy["key_path"])
        if not stat.S_ISREG(metadata.st_mode):
            return Outcome("unknown", "Expected key path is not a regular nonsymlink file", evidence)
        evidence.update({"mode": format(stat.S_IMODE(metadata.st_mode), "04o"), "uid": metadata.st_uid})
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != policy["expected_uid"]:
            return Outcome("mismatch", "Key owner or exact mode 0600 differs from policy", evidence)
        return Outcome("verified", "Key owner and exact POSIX mode 0600 confirmed; ACLs not assessed", evidence)
    except OSError:
        return Outcome("unknown", "Key metadata unavailable", evidence)


def cases(config):
    yield Case("key_nip49_envelope", envelope)
    yield Case("key_owner_mode_0600", permissions)
