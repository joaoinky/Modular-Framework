from copy import deepcopy
import json
import math
from pathlib import Path

from nvg_key_material.files import Limits, read_regular

DEFAULT = {
    "schema_version": 1,
    "target": {"description": "Local disposable namespace simulation"},
    "execution": {"timeout_seconds": 5, "case_timeouts": {}},
    "network": {
        "mode": "simulation",
        "library": "/usr/lib/neovanguard/neo-rede.sh",
        "reference": "/usr/lib/neovanguard/network-policies.json",
        "rules_dir": None,
    },
    "key_exposure": {"enabled": False, "key_path": None, "expected_uid": None,
                     "limits": {}},
    "extensions": {},
}


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def positive_timeout(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 300:
        raise ValueError("Timeout must be positive, finite and at most 300 seconds")


def load_config(filename=None):
    value = deepcopy(DEFAULT)
    base = Path.cwd()
    if filename:
        read = read_regular(filename, 262144)
        if read.partial:
            raise ValueError("Configuration incomplete")
        supplied = json.loads(read.data, object_pairs_hook=no_duplicates)
        if not isinstance(supplied, dict) or set(supplied) - set(DEFAULT):
            raise ValueError("Unknown configuration field")
        for key, child in supplied.items():
            if isinstance(value[key], dict):
                if not isinstance(child, dict) or (key != "extensions" and set(child) - set(value[key])):
                    raise ValueError("Unknown configuration section field")
                value[key].update(child)
            else:
                value[key] = child
        base = Path(filename).absolute().parent
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported configuration schema")
    if not isinstance(value["target"]["description"], str) or not value["target"]["description"].strip():
        raise ValueError("Target description required")
    positive_timeout(value["execution"]["timeout_seconds"])
    overrides = value["execution"]["case_timeouts"]
    if not isinstance(overrides, dict):
        raise ValueError("Case timeouts must be an object")
    for key, timeout in overrides.items():
        if not isinstance(key, str):
            raise ValueError("Invalid case timeout ID")
        positive_timeout(timeout)
    network = value["network"]
    if network["mode"] != "simulation":
        raise ValueError("Only local namespace simulation is supported")
    for key in ("library", "reference"):
        if not isinstance(network[key], str) or not Path(network[key]).is_absolute():
            raise ValueError("Native library and reference must have absolute paths")
    if network["rules_dir"] is not None:
        if not isinstance(network["rules_dir"], str) or not network["rules_dir"]:
            raise ValueError("Invalid rules directory")
        network["rules_dir"] = str((base / network["rules_dir"]).absolute())
    policy = value["key_exposure"]
    if type(policy["enabled"]) is not bool:
        raise ValueError("Key inspection requires a boolean opt-in")
    if policy["key_path"] is not None:
        if not isinstance(policy["key_path"], str) or not Path(policy["key_path"]).is_absolute():
            raise ValueError("Key path must be explicitly absolute")
    if policy["expected_uid"] is not None and (type(policy["expected_uid"]) is not int or policy["expected_uid"] < 0):
        raise ValueError("Invalid expected owner")
    if policy["enabled"] and (policy["key_path"] is None or policy["expected_uid"] is None):
        raise ValueError("Key opt-in requires a path and expected UID")
    if not isinstance(policy["limits"], dict):
        raise ValueError("Invalid read limits")
    Limits(**policy["limits"])
    return value
