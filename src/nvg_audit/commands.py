"""Bounded command capture; never include raw stderr in evidence."""

import os
import selectors
import subprocess
import time

from nvg_key_material.files import Unavailable

SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def command(argv, data=None, timeout=5, limit=262144):
    env = {"PATH": SYSTEM_PATH, "LC_ALL": "C", "PYTHONPATH": os.environ.get("PYTHONPATH", "")}
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    except OSError:
        raise Unavailable("Required command unavailable") from None
    output = bytearray()
    pending = memoryview(data.encode() if isinstance(data, str) else data or b"")
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ)
            if proc.stdin:
                os.set_blocking(proc.stdin.fileno(), False)
                if pending:
                    selector.register(proc.stdin, selectors.EVENT_WRITE)
                else:
                    proc.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Unavailable("Command timed out")
                for key, _ in selector.select(remaining):
                    if key.fileobj is proc.stdin:
                        try:
                            count = os.write(proc.stdin.fileno(), pending[:4096])
                            pending = pending[count:]
                        except BrokenPipeError:
                            pending = memoryview(b"")
                        if not pending:
                            selector.unregister(proc.stdin)
                            proc.stdin.close()
                    else:
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(proc.stdout)
                        output.extend(chunk)
                        if len(output) > limit:
                            raise Unavailable("Command output limit exceeded")
        try:
            code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise Unavailable("Command timed out") from None
        return code, output.decode("utf-8")
    except (OSError, UnicodeError):
        raise Unavailable("Command output unavailable") from None
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()


def checked(argv, data=None):
    code, output = command(argv, data)
    if code:
        raise Unavailable("Command failed, unsupported, or permission denied")
    return output
