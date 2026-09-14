"""Trusted plugins, bounded child processes, and nonbinary aggregation."""

from dataclasses import asdict
from datetime import datetime, timezone
import importlib
import json
import os
import pkgutil
import re
import selectors
import signal
import time

from . import __version__
from .models import Case, Outcome, STATES
from .privacy import redact

IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*\Z")
MAX_RESULT_BYTES = 262144


def discover(package="nvg_audit.plugins"):
    modules, errors = {}, {}
    root = importlib.import_module(package)
    for item in sorted(pkgutil.iter_modules(root.__path__), key=lambda item: item.name):
        if not item.name.endswith("_plugin"):
            continue
        name = item.name[:-7]
        try:
            module = importlib.import_module(package + "." + item.name)
            if not IDENTIFIER.fullmatch(name) or not callable(getattr(module, "cases", None)):
                raise ValueError("Invalid plugin")
            modules[name] = module
        except Exception:
            errors[name] = "Plugin import or interface unavailable"
    return modules, errors


def isolated(run, config, timeout):
    """Fork preserves injectable test collectors; a process group owns descendants."""
    if not hasattr(os, "fork"):
        return Outcome("unknown", "Case isolation requires Linux/POSIX")
    read_fd, write_fd = os.pipe()
    started = time.monotonic()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.setsid()
            with open(os.devnull, "wb") as sink:
                os.dup2(sink.fileno(), 1)
                os.dup2(sink.fileno(), 2)
            try:
                result = run(config)
                if (not isinstance(result, Outcome) or result.state not in STATES
                        or not isinstance(result.reason, str) or not result.reason.strip()
                        or not isinstance(result.evidence, dict)):
                    raise ValueError("Invalid result")
                raw = json.dumps(redact(asdict(result)), allow_nan=False).encode()
                if len(raw) > MAX_RESULT_BYTES:
                    raise ValueError("Result too large")
            except BaseException:
                raw = b'{"state":"unknown","reason":"Case failed or returned invalid evidence","evidence":{}}'
            with os.fdopen(write_fd, "wb") as pipe:
                pipe.write(raw)
        finally:
            os._exit(0)
    os.close(write_fd)
    collected = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(read_fd, selectors.EVENT_READ)
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0 or not selector.select(remaining):
                    return Outcome("unknown", "Case timeout; process group terminated")
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                collected.extend(chunk)
                if len(collected) > MAX_RESULT_BYTES:
                    return Outcome("unknown", "Case output limit exceeded")
        document = json.loads(collected)
        return Outcome(**document)
    except (OSError, ValueError, TypeError):
        return Outcome("unknown", "Case process ended without valid evidence")
    finally:
        os.close(read_fd)
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os.waitpid(pid, 0)


def execute(config, selected=None, modules=None, errors=None):
    if modules is None:
        modules, errors = discover()
    errors = errors or {}
    names = sorted(set(modules) | set(errors)) if selected is None else list(dict.fromkeys(selected))
    if not names or any(name not in modules and name not in errors for name in names):
        raise ValueError("No plugins selected or unknown plugin")
    report = {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
              "framework_version": __version__, "target": redact(config["target"]),
              "plugins_executed": names, "results": []}
    def append(plugin, case_id, outcome, elapsed=0):
        report["results"].append({"plugin": plugin, "case_id": case_id,
                                  **asdict(outcome), "duration_ms": round(elapsed * 1000, 3)})
    for name in names:
        if name in errors:
            append(name, "engine_discovery", Outcome("unknown", errors[name]))
            continue
        seen = set()
        try:
            for case in modules[name].cases(config):
                if (not isinstance(case, Case) or not IDENTIFIER.fullmatch(case.case_id)
                        or case.case_id.startswith("engine_") or case.case_id in seen
                        or not callable(case.run)):
                    raise ValueError("Invalid case")
                seen.add(case.case_id)
                timeout = config["execution"]["case_timeouts"].get(
                    case.case_id, config["execution"]["timeout_seconds"])
                start = time.monotonic()
                outcome = isolated(case.run, config, timeout)
                append(name, case.case_id, outcome, time.monotonic() - start)
            if not seen:
                raise ValueError("Empty plugin")
        except Exception:
            append(name, "engine_contract", Outcome("unknown", "Plugin enumeration empty, failed, or invalid"))
    report["summary"] = {state: sum(r["state"] == state for r in report["results"]) for state in STATES}
    return report


def exit_code(report):
    return 1 if report["summary"]["mismatch"] else 3 if report["summary"]["unknown"] else 0
