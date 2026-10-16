"""Exercise exact inbound callbacks and established-flow expiry in isolated netns."""

import signal
import socket
import subprocess
import time
import uuid
import os

from deadbolt.ingress_firewall import IngressFirewall


LOCAL = "192.168.1.102"
SOURCE = "192.168.1.205"
OTHER = "192.168.1.206"
OUTSIDE = "192.168.2.205"


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def firewall_run(argv, data):
    if argv == ["/usr/sbin/ufw", "status", "verbose"]:
        return subprocess.CompletedProcess(argv, 0,
            "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n", "")
    return subprocess.run(argv, input=data, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, check=False, timeout=10)


def probe(source, port):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LOCAL, port))
    listener.listen(1)
    client = socket.socket()
    client.bind((source, 0))
    client.settimeout(0.6)
    try:
        client.connect((LOCAL, port))
        return True
    except (OSError, TimeoutError):
        return False
    finally:
        client.close()
        listener.close()


def probe6(source, port):
    listener = socket.socket(socket.AF_INET6)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("fd00::102", port))
    listener.listen(1)
    client = socket.socket(socket.AF_INET6)
    client.bind((source, 0))
    client.settimeout(0.6)
    try:
        client.connect(("fd00::102", port))
        return True
    except (OSError, TimeoutError):
        return False
    finally:
        client.close()
        listener.close()


def held_connection(stop):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LOCAL, 6969))
    listener.listen(1)
    listener.settimeout(3)
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            client = socket.socket()
            client.bind((SOURCE, 0))
            client.settimeout(3)
            client.connect((LOCAL, 6969))
            client.sendall(b"before")
            child.sendall(b"ready")
            child.recv(1)
            client.sendall(b"after")
            child.sendall(b"sent")
            child.recv(1)
        except Exception as exc:
            child.sendall(f"error:{type(exc).__name__}".encode())
        finally:
            os._exit(0)
    child.close()
    try:
        connection, _ = listener.accept()
        connection.settimeout(3)
        assert connection.recv(6) == b"before"
        assert parent.recv(5) == b"ready"
        stop()
        parent.sendall(b"x")
        parent.settimeout(3)
        outcome = parent.recv(64)
        assert outcome == b"sent" or outcome.startswith(b"error:"), outcome
        connection.settimeout(0.6)
        try:
            leaked = connection.recv(5)
        except socket.timeout:
            leaked = None
        assert leaked in (None, b""), f"established callback survived stop: {leaked!r}"
        if outcome == b"sent":
            parent.sendall(b"x")
        connection.close()
    finally:
        parent.close()
        listener.close()
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


run("ip", "link", "set", "lo", "up")
run("ip", "link", "add", "dummy0", "type", "dummy")
run("ip", "link", "set", "dummy0", "up")
for ip in (LOCAL, SOURCE, OTHER, OUTSIDE):
    run("ip", "address", "add", f"{ip}/32", "dev", "dummy0")
for ip in ("fd00::102", "fd00::205", "fd00::206"):
    run("ip", "-6", "address", "add", f"{ip}/128", "dev", "dummy0")
run("iptables", "-N", "ufw-before-input")
run("iptables", "-A", "INPUT", "-j", "ufw-before-input")
run("iptables", "-A", "ufw-before-input", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
run("iptables", "-A", "ufw-before-input", "-d", LOCAL, "-j", "DROP")
run("iptables", "-A", "ufw-before-input", "-s", "10.0.0.1", "-j", "DROP")
run("ip6tables", "-N", "ufw-before-input")
run("ip6tables", "-A", "INPUT", "-j", "ufw-before-input")
run("ip6tables", "-A", "ufw-before-input", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
run("ip6tables", "-A", "ufw-before-input", "-d", "fd00::102", "-j", "DROP")
baseline_output = subprocess.check_output(["iptables", "-S", "OUTPUT"])

firewall = IngressFirewall(firewall_run)
record = {"source": f"{SOURCE}/32", "local_ip": LOCAL, "protocol": "tcp",
          "port_start": 6969, "port_end": 6973}
for scenario in ("revoke", "expiry"):
    request_id = str(uuid.uuid4())
    now = time.time()
    expiry = int(now) + 5
    try:
        firewall.ensure_grant(record, request_id, expiry, now)
    except Exception:
        subprocess.run(["nft", "-a", "list", "table", "inet", "deadbolt_ingress"], check=False)
        subprocess.run(["iptables", "-S", "ufw-before-input"], check=False)
        name, tag = firewall._identity(request_id, expiry)
        print("element:", firewall._nft("get", "element", "inet", firewall.TABLE,
              name, "{", record["source"], "}", missing_ok=True), flush=True)
        print("positions:", firewall._ufw_positions(4, tag), flush=True)
        for allowed in (True, False):
            rule = firewall._ufw_rule(record, tag, expiry, allow=allowed)
            print("check", allowed, firewall._iptables(4, "-C", firewall.UFW_CHAIN,
                  *rule, missing_ok=True), flush=True)
        raise
    firewall.ensure_grant(record, request_id, expiry, now)  # Idempotent.
    if scenario == "revoke":
        # A UFW reload removes the runtime pair; reconcile must reinstall it
        # ahead of the ESTABLISHED accept and the default incoming deny.
        run("iptables", "-F", "ufw-before-input")
        run("iptables", "-A", "ufw-before-input", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
        run("iptables", "-A", "ufw-before-input", "-d", LOCAL, "-j", "DROP")
        run("iptables", "-A", "ufw-before-input", "-s", "10.0.0.1", "-j", "DROP")
        firewall.ensure_grant(record, request_id, expiry, time.time())
    assert probe(SOURCE, 6970), "approved source/port was not allowed"
    assert not probe(OTHER, 6970), "unapproved source was allowed"
    assert not probe(SOURCE, 6974), "unapproved port was allowed"
    if scenario == "revoke":
        held_connection(lambda: firewall.revoke(record, request_id, expiry))
    else:
        held_connection(lambda: time.sleep(max(0, expiry - time.time()) + 1))
        firewall.revoke(record, request_id, expiry)
    firewall.revoke(record, request_id, expiry)
    assert not probe(SOURCE, 6970), "revoke/expiry left a new callback path"

# A fresh approval replaces the same exact scope. The first grant's retained
# deny must not shadow the second grant's allow in nftables or UFW.
old_id, new_id = str(uuid.uuid4()), str(uuid.uuid4())
now = time.time()
old_expiry = int(now) + 30
firewall.ensure_grant(record, old_id, old_expiry, now)
firewall.revoke(record, old_id, old_expiry)
new_expiry = int(time.time()) + 60
firewall.ensure_grant(record, new_id, new_expiry, time.time())
assert probe(SOURCE, 6970), "replacement grant was shadowed by old deny"
assert not probe(OTHER, 6970), "replacement allowed a different source"
firewall.revoke(record, new_id, new_expiry)
assert not probe(SOURCE, 6970), "replacement revoke left a callback path"

cidr_id = str(uuid.uuid4())
cidr_record = {**record, "source": "192.168.1.0/24", "port_start": 6975,
               "port_end": 6975}
now = time.time()
cidr_expiry = int(now) + 30
try:
    firewall.ensure_grant(cidr_record, cidr_id, cidr_expiry, now)
except Exception:
    subprocess.run(["nft", "-a", "list", "table", "inet", "deadbolt_ingress"], check=False)
    subprocess.run(["iptables", "-S", "ufw-before-input"], check=False)
    name, tag = firewall._identity(cidr_id, cidr_expiry)
    print("cidr element", firewall._nft("get", "element", "inet", firewall.TABLE,
          name, "{", cidr_record["source"], "}", missing_ok=True), flush=True)
    print("cidr positions", firewall._ufw_positions(4, tag), flush=True)
    for allowed in (True, False):
        rule = firewall._ufw_rule(cidr_record, tag, cidr_expiry, allow=allowed)
        print("cidr check", allowed, firewall._iptables(4, "-C", firewall.UFW_CHAIN,
              *rule, missing_ok=True), flush=True)
    raise
assert probe(SOURCE, 6975) and probe(OTHER, 6975)
assert not probe(OUTSIDE, 6975), "outside-CIDR source was allowed"
firewall.revoke(cidr_record, cidr_id, cidr_expiry)
assert not probe(SOURCE, 6975)

v6_id = str(uuid.uuid4())
v6_record = {"source": "fd00::205/128", "local_ip": "fd00::102", "protocol": "tcp",
             "port_start": 6976, "port_end": 6976}
now = time.time()
v6_expiry = int(now) + 30
firewall.ensure_grant(v6_record, v6_id, v6_expiry, now)
assert probe6("fd00::205", 6976)
assert not probe6("fd00::206", 6976)
firewall.revoke(v6_record, v6_id, v6_expiry)
assert not probe6("fd00::205", 6976)
assert subprocess.check_output(["iptables", "-S", "OUTPUT"]) == baseline_output
run("iptables", "-C", "ufw-before-input", "-s", "10.0.0.1", "-j", "DROP")
run("iptables", "-C", "ufw-before-input", "-d", LOCAL, "-j", "DROP")

print("exact ingress source/port, established-flow expiry/revoke, idempotency: OK")
