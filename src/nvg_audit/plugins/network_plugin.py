from functools import partial
import json
import os
import shutil
import sys

from nvg_key_material.files import Unavailable

from ..commands import command, SYSTEM_PATH
from ..models import Case, Outcome, STATES

CASE_IDS = (
    "nvg06_established_sessions_direct",
    "nvg07_dns_leak_lan_resolver",
    "nvg08_airgap_false_success",
    "nvg10_vpn_dns_leak",
    "nvg11_vpn_udp_unrestricted",
)


def run_case(case_id, config):
    evidence = {"scope": "documented_rules_simulation", "real_nos": False}
    missing = [name for name in ("ip", "nft", "unshare") if not shutil.which(name, path=SYSTEM_PATH)]
    if missing:
        evidence["missing_commands"] = missing
        return Outcome("unknown", "Required namespace/network tools unavailable", evidence)
    try:
        parent_net = str(os.stat("/proc/self/ns/net").st_ino)
        parent_user = str(os.stat("/proc/self/ns/user").st_ino)
        args = ["unshare", "--user", "--map-root-user", "--net", sys.executable,
                "-m", "nvg_audit.net_worker", case_id, parent_net, parent_user]
        timeout = config["execution"]["case_timeouts"].get(case_id, config["execution"]["timeout_seconds"])
        code, raw = command(args, json.dumps(config["network"]), timeout=timeout)
        if code:
            return Outcome("unknown", "Namespace creation or worker execution denied or failed", evidence)
        doc = json.loads(raw)
        if (doc["state"] not in STATES or not isinstance(doc["reason"], str)
                or not isinstance(doc["evidence"], dict)
                or (doc["state"] == "verified" and doc["evidence"].get("namespace_real") is not True)):
            raise ValueError("Invalid worker result")
        return Outcome(doc["state"], doc["reason"], {**evidence, **doc["evidence"]})
    except (Unavailable, OSError, ValueError, KeyError, TypeError):
        return Outcome("unknown", "Network query failed, timed out, or returned invalid evidence", evidence)


def cases(config):
    for case_id in CASE_IDS:
        yield Case(case_id, partial(run_case, case_id))
