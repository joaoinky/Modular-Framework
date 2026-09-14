"""Documented airgap observation and simulated cache transition, not nOS code."""

import json
import os

from .models import Outcome


def observe(links, radios):
    active, unblocked, incomplete = [], [], False
    if not isinstance(links, list) or not links:
        incomplete = True
    else:
        for link in links:
            if (not isinstance(link, dict) or not isinstance(link.get("ifname"), str)
                    or not isinstance(link.get("flags"), list)
                    or not all(isinstance(flag, str) for flag in link["flags"])):
                incomplete = True
                continue
            if "LOOPBACK" not in link["flags"] and "UP" in link["flags"]:
                active.append(link["ifname"])
    devices = radios.get("rfkilldevices") if isinstance(radios, dict) else None
    if not isinstance(devices, list):
        incomplete = True
    else:
        for radio in devices:
            if not isinstance(radio, dict):
                incomplete = True
                continue
            soft, hard = radio.get("soft"), radio.get("hard")
            if (type(radio.get("id")) is not int or not isinstance(radio.get("type"), str)
                    or soft not in ("blocked", "unblocked") or hard not in ("blocked", "unblocked")):
                incomplete = True
                continue
            if soft == hard == "unblocked":
                unblocked.append(radio["id"])
    evidence = {"active_interfaces": active, "unblocked_radio_ids": unblocked,
                "incomplete": incomplete, "radios_simulated": True}
    if active or unblocked:
        return Outcome("mismatch", "Known interface or radio activity contradicts isolation", evidence)
    if incomplete:
        return Outcome("unknown", "Interface or radio query incomplete", evidence)
    return Outcome("verified", "Enumerated interfaces disabled and simulated radios blocked", evidence)


def cache_observation(path, observation, operation_ok=True):
    """Simulate invalidation-before-verification and atomic creation in a temp dir."""
    path.unlink(missing_ok=True)
    if not operation_ok or observation.state != "verified":
        return False
    temporary = path.with_suffix(".tmp")
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"state": observation.state}, stream)
        os.replace(temporary, path)
        return True
    finally:
        temporary.unlink(missing_ok=True)
