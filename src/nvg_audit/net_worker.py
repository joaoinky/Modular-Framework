"""Real kernel traffic in two anonymous namespaces; never enter the host network."""

from contextlib import contextmanager
from dataclasses import asdict
import errno
from importlib import resources
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time

from nvg_key_material.files import Unavailable, read_regular

from .airgap import cache_observation, observe
from .commands import checked, SYSTEM_PATH
from .models import Outcome

BASELINE = """flush ruleset
table inet baseline {
 counter established {}
 chain output { type filter hook output priority 0; policy accept;
   ct state established,related counter name established accept
 }
 chain nat_output { type nat hook output priority -100; policy accept; }
}
"""
ADDRESSES = ("192.168.50.1", "fd00:50::1", "198.18.0.2", "2001:db8::2",
             "198.18.0.3", "2001:db8::3")


def namespace_id(kind="net"):
    return os.stat("/proc/self/ns/" + kind).st_ino


def guard(parent_net, parent_user=None):
    actual_parent = Path("/proc") / str(os.getppid()) / "ns"
    if namespace_id() in (int(parent_net), (actual_parent / "net").stat().st_ino):
        raise Unavailable("Refusing network mutation in the invoking namespace")
    if parent_user is not None and namespace_id("user") in (
            int(parent_user), (actual_parent / "user").stat().st_ino):
        raise Unavailable("Worker lacks a disposable user namespace")


class EchoService:
    def __init__(self, local=False):
        self.selector = selectors.DefaultSelector()
        self.running = True
        self.failed = False
        ports = [(socket.SOCK_DGRAM, 9053, b"dns"), (socket.SOCK_STREAM, 9040, b"trans")] if local else [
            (socket.SOCK_DGRAM, port, b"peer") for port in (53, 18080, 51820, 1194)] + [
            (socket.SOCK_STREAM, port, b"peer") for port in (53, 18080)]
        try:
            for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
                for kind, port, label in ports:
                    sock = socket.socket(family, kind)
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        if family == socket.AF_INET6:
                            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        sock.bind((host, port))
                        if kind == socket.SOCK_STREAM:
                            sock.listen(16)
                        sock.setblocking(False)
                        self.selector.register(sock, selectors.EVENT_READ,
                                               ("udp" if kind == socket.SOCK_DGRAM else "listen", label, bytearray()))
                    except BaseException:
                        sock.close()
                        raise
        except BaseException:
            self.close()
            raise
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        try:
            while self.running:
                for key, _ in self.selector.select(0.05):
                    sock = key.fileobj
                    kind, label, buffer = key.data
                    if kind == "listen":
                        conn, _ = sock.accept()
                        conn.setblocking(False)
                        self.selector.register(conn, selectors.EVENT_READ, ("tcp", label, bytearray()))
                    elif kind == "udp":
                        data, address = sock.recvfrom(4096)
                        sock.sendto(label + b":" + data, address)
                    else:
                        try:
                            data = sock.recv(4096)
                            if not data:
                                self.selector.unregister(sock)
                                sock.close()
                                continue
                            buffer.extend(data)
                            while b"\n" in buffer:
                                line, _, rest = buffer.partition(b"\n")
                                buffer[:] = rest
                                sock.sendall(label + b":" + line + b"\n")
                        except (ConnectionError, BlockingIOError):
                            self.selector.unregister(sock)
                            sock.close()
        except (OSError, ValueError):
            if self.running:
                self.failed = True

    def close(self):
        self.running = False
        if hasattr(self, "thread"):
            self.thread.join(1)
        for key in list(self.selector.get_map().values()):
            key.fileobj.close()
        self.selector.close()


def read_line(stream, timeout=5):
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise Unavailable("Peer control timed out")
        line = stream.readline(4096)
        if not line:
            raise Unavailable("Peer control failed")
        return json.loads(line)


def peer_main(parent_net):
    guard(parent_net)
    print(json.dumps({"ready": True, "namespace": namespace_id()}), flush=True)
    if sys.stdin.readline().strip() != "start":
        return
    checked(["ip", "link", "set", "lo", "up"])
    checked(["ip", "link", "set", "peer0", "up"])
    for address in ADDRESSES:
        prefix = "/24" if address == "192.168.50.1" else "/64" if address == "fd00:50::1" else "/128" if ":" in address else "/32"
        args = ["ip", "addr", "add", address + prefix, "dev", "peer0"]
        if ":" in address:
            args.append("nodad")
        checked(args)
    echo = EchoService()
    try:
        print(json.dumps({"ready": True}), flush=True)
        for line in sys.stdin:
            if line.strip() != "health":
                break
            print(json.dumps({"ready": not echo.failed}), flush=True)
    finally:
        echo.close()


class Lab:
    def __init__(self, policy, parent_net, parent_user):
        guard(parent_net, parent_user)
        self.policy = policy
        self.parent_net = parent_net
        self.parent_user = parent_user
        self.peer = None
        self.local = None
        self.sequence = 0

    def __enter__(self):
        try:
            checked(["ip", "link", "set", "lo", "up"])
            checked(["ip", "link", "add", "nvgvpn0", "type", "dummy"])
            checked(["ip", "link", "set", "nvgvpn0", "up"])
            self.peer = subprocess.Popen(["unshare", "--net", sys.executable, "-m", "nvg_audit.net_worker",
                                           "--peer", str(namespace_id())], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                          env={"PATH": SYSTEM_PATH, "LC_ALL": "C",
                                               "PYTHONPATH": os.environ.get("PYTHONPATH", "")})
            ready = read_line(self.peer.stdout)
            if not ready.get("ready") or ready.get("namespace") == namespace_id():
                raise Unavailable("Peer namespace isolation failed")
            checked(["ip", "link", "add", "audit0", "type", "veth", "peer", "name", "peer0"])
            checked(["ip", "link", "set", "peer0", "netns", str(self.peer.pid)])
            checked(["ip", "link", "set", "audit0", "up"])
            checked(["ip", "addr", "add", "192.168.50.2/24", "dev", "audit0"])
            checked(["ip", "addr", "add", "fd00:50::2/64", "dev", "audit0", "nodad"])
            checked(["ip", "route", "add", "198.18.0.0/24", "via", "192.168.50.1"])
            checked(["ip", "-6", "route", "add", "2001:db8::/64", "via", "fd00:50::1"])
            self.peer.stdin.write("start\n")
            self.peer.stdin.flush()
            if not read_line(self.peer.stdout).get("ready"):
                raise Unavailable("Peer listeners unavailable")
            self.local = EchoService(local=True)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.local:
            self.local.close()
        if self.peer:
            self.peer.stdin.close()
            try:
                self.peer.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.peer.kill()
                self.peer.wait()
            self.peer.stdout.close()

    def health(self):
        if self.local.failed or self.peer.poll() is not None:
            raise Unavailable("Echo control unavailable")
        self.peer.stdin.write("health\n")
        self.peer.stdin.flush()
        if not read_line(self.peer.stdout).get("ready"):
            raise Unavailable("Peer echo failed")

    def apply(self, text):
        guard(self.parent_net, self.parent_user)
        checked(["nft", "-f", "-"], text)

    def rules(self, profile):
        if self.policy["rules_dir"] is None:
            return resources.files("nvg_audit").joinpath("rules", profile + ".nft").read_text()
        read = read_regular(Path(self.policy["rules_dir"]) / (profile + ".nft"), 262144)
        if read.partial:
            raise Unavailable("Rules reference incomplete")
        text = read.data.decode("utf-8")
        if "include" in text:
            raise Unavailable("External nft includes are outside fixture scope")
        return text

    def counter(self, name, table="audit_filter"):
        doc = json.loads(checked(["nft", "-j", "list", "counter", "inet", table, name]))
        entries = [entry["counter"] for entry in doc["nftables"] if "counter" in entry]
        if (len(entries) != 1 or type(entries[0].get("packets")) is not int
                or entries[0]["packets"] < 0):
            raise Unavailable("Kernel counter incomplete")
        return entries[0]["packets"]

    @contextmanager
    def channel(self, address, port, protocol):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
        try:
            sock.settimeout(1)
            sock.connect((address, port))
            yield sock
        finally:
            sock.close()

    def exchange(self, sock, window=0.25):
        self.sequence += 1
        token = ("probe-%08d\n" % self.sequence).encode()
        end = time.monotonic() + window
        try:
            sock.settimeout(window)
            sock.sendall(token)
            buffer = bytearray()
            while time.monotonic() < end:
                sock.settimeout(max(0.001, end - time.monotonic()))
                data = sock.recv(4096)
                if not data:
                    raise Unavailable("Echo connection closed unexpectedly")
                buffer.extend(data)
                for label in (b"peer", b"dns", b"trans"):
                    if label + b":" + token in buffer:
                        return label.decode()
            return None
        except socket.timeout:
            # An observation window is meaningful only with a kernel verdict and controls.
            return None
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES):
                return None
            raise Unavailable("Traffic probe failed without a measurable verdict") from None

    def control(self, sock):
        if self.exchange(sock, 1.5) != "peer":
            raise Unavailable("Positive peer control failed")

    def block(self, address, port, protocol, profile, counter="direct_drop", rules=None):
        self.apply(BASELINE)
        with self.channel(address, port, protocol) as sock:
            self.control(sock)
            self.control(sock)
            if self.counter("established", "baseline") <= 0:
                raise Unavailable("Conntrack baseline not confirmed")
            self.apply(rules or self.rules(profile))
            before = self.counter(counter)
            response = self.exchange(sock)
            after = self.counter(counter)
            self.health()
            self.apply(BASELINE)
            self.control(sock)
        if response is not None:
            state = "mismatch"
        elif after > before:
            state = "verified"
        else:
            state = "unknown"
        return {"profile": profile, "family": "ipv6" if ":" in address else "ipv4",
                "protocol": protocol, "port": port, "state": state,
                "drop_packets": after - before, "peer_received": response is not None,
                "controls": "before_and_after"}

    def delivered(self, address, port, protocol, profile, expected, rules=None):
        self.apply(BASELINE)
        with self.channel(address, port, protocol) as baseline:
            self.control(baseline)
        self.apply(rules or self.rules(profile))
        try:
            with self.channel(address, port, protocol) as sock:
                response = self.exchange(sock, 1)
        except (OSError, Unavailable):
            response = None
        self.health()
        self.apply(BASELINE)
        with self.channel(address, port, protocol) as recovery:
            self.control(recovery)
        state = "verified" if response == expected else "mismatch" if response is not None else "unknown"
        return {"profile": profile, "family": "ipv6" if ":" in address else "ipv4",
                "protocol": protocol, "port": port, "state": state,
                "delivery": response, "expected": expected, "controls": "before_and_after"}

    def block_new(self, address, port, protocol, profile, counter="direct_drop"):
        self.apply(BASELINE)
        with self.channel(address, port, protocol) as baseline:
            self.control(baseline)
        self.apply(self.rules(profile))
        before = self.counter(counter)
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.3)
            try:
                sock.connect((address, port))
                response = self.exchange(sock)
            except socket.timeout:
                response = None
            except OSError as error:
                if error.errno not in (errno.EPERM, errno.EACCES):
                    raise Unavailable("New flow failed without a measured verdict") from None
                response = None
            after = self.counter(counter)
        self.health()
        self.apply(BASELINE)
        with self.channel(address, port, protocol) as recovery:
            self.control(recovery)
        state = "mismatch" if response is not None else "verified" if after > before else "unknown"
        return {"profile": profile, "family": "ipv6" if ":" in address else "ipv4",
                "protocol": protocol, "port": port, "flow": "new", "state": state,
                "drop_packets": after - before, "peer_received": response is not None,
                "controls": "before_and_after"}


def aggregate(observations):
    states = [item["state"] for item in observations]
    state = "mismatch" if "mismatch" in states else "verified" if states and all(s == "verified" for s in states) else "unknown"
    return Outcome(state, {"verified": "Documented scenario confirmed by kernel traffic and controls",
                           "mismatch": "Traffic or marker behavior contradicts the documented scenario",
                           "unknown": "At least one probe lacks sufficient measured evidence"}[state],
                   {"namespace_real": True, "dummy_interface": "nvgvpn0", "observations": observations})


def traffic_case(lab, case_id):
    observations = []
    if case_id == "nvg06_established_sessions_direct":
        for profile in ("tor", "killswitch-tor"):
            for address in ("198.18.0.3", "2001:db8::3"):
                for protocol in ("tcp", "udp"):
                    observations.append(lab.block(address, 18080, protocol, profile))
                    # Same documented positive-control substitution as the nOS test description.
                    authorized = lab.rules(profile).replace("meta skuid 43", "meta skuid 0")
                    observations.append(lab.delivered(address, 18080, protocol, profile, "peer", authorized))
    elif case_id == "nvg07_dns_leak_lan_resolver":
        for address in ("192.168.50.1", "fd00:50::1", "198.18.0.3", "2001:db8::3"):
            for protocol in ("tcp", "udp"):
                observations.append(lab.delivered(address, 53, protocol, "tor", "dns" if protocol == "udp" else "trans"))
                observations.append(lab.block(address, 53, protocol, "tor", "dns_drop"))
        for protocol in ("tcp", "udp"):
            observations.append(lab.delivered("192.168.50.1", 18080, protocol, "tor", "peer"))
    elif case_id == "nvg10_vpn_dns_leak":
        for address in ("192.168.50.1", "fd00:50::1"):
            for protocol in ("tcp", "udp"):
                observations.append(lab.block(address, 53, protocol, "killswitch-vpn", "dns_drop"))
                observations.append(lab.block_new(address, 53, protocol, "killswitch-vpn", "dns_drop"))
                observations.append(lab.delivered(address, 18080, protocol, "killswitch-vpn", "peer"))
    elif case_id == "nvg11_vpn_udp_unrestricted":
        for address in ("198.18.0.3", "2001:db8::3"):
            for port in (51820, 1194):
                observations.append(lab.block(address, port, "udp", "killswitch-vpn"))
                observations.append(lab.block_new(address, port, "udp", "killswitch-vpn"))
        for address, good, wrong in (("198.18.0.2", 51820, 1194), ("2001:db8::2", 1194, 51820)):
            observations.append(lab.block(address, wrong, "udp", "killswitch-vpn"))
            observations.append(lab.block_new(address, wrong, "udp", "killswitch-vpn"))
            observations.append(lab.delivered(address, good, "udp", "killswitch-vpn", "peer"))
    else:
        raise Unavailable("Unknown traffic case")
    return aggregate(observations)


def airgap_case(lab):
    observations = []
    blocked = {"rfkilldevices": [{"id": 0, "type": "wlan", "soft": "blocked", "hard": "unblocked"}]}
    unlocked = {"rfkilldevices": [{"id": 0, "type": "wlan", "soft": "unblocked", "hard": "unblocked"}]}
    with tempfile.TemporaryDirectory(prefix="nvg-airgap-") as directory:
        marker = Path(directory) / "airgap"
        def check(label, radios, expected, operation_ok=True):
            links = json.loads(checked(["ip", "-j", "link", "show"]))
            result = observe(links, radios)
            # Seed a stale marker on each transition, so invalidation is exercised too.
            marker.write_text('{"state":"verified"}')
            wrote = cache_observation(marker, result, operation_ok)
            wanted = expected == "verified" and operation_ok
            correct = result.state == expected and wrote == wanted and marker.exists() == wanted
            observations.append({"scenario": label, "state": "verified" if correct else "mismatch",
                                 "observed_state": result.state, "marker_created": wrote})
        check("interfaces_still_up", blocked, "mismatch")
        check("activity_and_failed_radio_query", None, "mismatch")
        checked(["ip", "link", "set", "audit0", "down"])
        checked(["ip", "link", "set", "nvgvpn0", "down"])
        check("radio_unblocked", unlocked, "mismatch")
        check("failed_radio_query", None, "unknown")
        check("malformed_radio_query", {}, "unknown")
        check("no_enumerated_radios", {"rfkilldevices": []}, "verified")
        check("blocked_radio", blocked, "verified")
        check("operation_failed_despite_isolation", blocked, "verified", operation_ok=False)
    result = aggregate(observations)
    result.evidence["radios_simulated"] = True
    result.evidence["marker_implementation"] = "framework_model_not_nos"
    return result


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--peer":
            peer_main(sys.argv[2])
            return 0
        if len(sys.argv) != 4:
            return 2
        case_id, parent_net, parent_user = sys.argv[1:]
        guard(parent_net, parent_user)
        policy = json.loads(sys.stdin.read(262144))
        with Lab(policy, parent_net, parent_user) as lab:
            result = airgap_case(lab) if case_id == "nvg08_airgap_false_success" else traffic_case(lab, case_id)
    except Exception:
        result = Outcome("unknown", "Namespace setup, command, observation, or peer control failed",
                         {"namespace_real": False})
    print(json.dumps(asdict(result), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
