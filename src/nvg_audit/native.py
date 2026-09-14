"""Read-only future integration adapter; never called by simulation cases."""

from datetime import datetime, timezone
import json
from pathlib import Path
import stat

from nvg_key_material.files import Unavailable

from .commands import command
from .config import no_duplicates
from .models import Outcome, STATES


def trusted_file(filename):
    path = Path(filename)
    if not path.is_absolute():
        raise Unavailable("Native path must be absolute")
    for item in (path, *path.parents):
        meta = item.lstat()
        kind_ok = stat.S_ISREG(meta.st_mode) if item == path else stat.S_ISDIR(meta.st_mode)
        if meta.st_uid != 0 or meta.st_mode & 0o022 or not kind_ok:
            raise Unavailable("Native file or ancestor has untrusted ownership, mode, or type")


def parse_observation(raw, code, mode, started, now):
    try:
        doc = json.loads(raw, object_pairs_hook=no_duplicates)
        verification = doc["verification"]
        state = verification["state"]
        observed = datetime.fromisoformat(doc["observed_at"].replace("Z", "+00:00"))
        domain = doc["airgap" if mode == "airgap" else "firewall"]
        if (type(doc["schema_version"]) is not int or doc["schema_version"] != 1
                or state not in STATES or verification["requested"] != mode
                or code != {"verified": 0, "mismatch": 1, "unknown": 2}[state]
                or observed.tzinfo is None or not started - 2 <= observed.timestamp() <= now + 2
                or domain["state"] not in STATES
                or (state == "verified" and domain["state"] != "verified")
                or (state == "verified" and mode != "airgap" and domain["mode"] != mode)):
            raise ValueError("Inconsistent contract")
        return Outcome(state, "Fresh native verification returned " + state,
                       {"requested": mode, "observed_at": observed.isoformat()})
    except (KeyError, TypeError, ValueError, AttributeError):
        return Outcome("unknown", "Native contract malformed, stale, or contradictory")


def verify(config, mode):
    if mode not in ("base", "tor", "killswitch-tor", "airgap"):
        return Outcome("unknown", "Native mode unsupported by this adapter")
    policy = config["network"]
    try:
        for path in (policy["library"], policy["reference"]):
            trusted_file(path)
        started = datetime.now(timezone.utc).timestamp()
        code, raw = command(["bash", "--noprofile", "--norc", "-c",
                             'source "$1" || exit 2; network_verify "$2"',
                             "nvg-read-only", policy["library"], mode])
        return parse_observation(raw, code, mode, started, datetime.now(timezone.utc).timestamp())
    except (Unavailable, OSError):
        return Outcome("unknown", "Native library, reference, or command unavailable or untrusted")
