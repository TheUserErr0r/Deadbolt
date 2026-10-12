"""Prove an established raw TCP flow stops at revoke and at nft timeout."""

import os
import signal
import socket
import subprocess
import time
import uuid

from deadbolt.outbound_firewall import ExactEgress


DESTINATION = "192.168.1.205"
HERMES_UID = 1001
PROXY_UID = 1002


def run(*argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)


def held_flow(port, stop_grant):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((DESTINATION, port))
    server.listen(1)
    server.settimeout(5)
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            os.setgid(HERMES_UID)
            os.setuid(HERMES_UID)
            client = socket.create_connection((DESTINATION, port), timeout=5)
            client.sendall(b"before")
            child.sendall(b"ready")
            child.recv(1)
            client.sendall(b"after")
            child.sendall(b"sent")
            child.recv(1)
            client.close()
        except Exception as exc:
            child.sendall(f"error:{type(exc).__name__}".encode())
        finally:
            os._exit(0)
    child.close()
    try:
        connection, _ = server.accept()
        connection.settimeout(5)
        assert connection.recv(6) == b"before"
        assert parent.recv(5) == b"ready"
        stop_grant()
        parent.sendall(b"x")
        parent.settimeout(5)
        outcome = parent.recv(64)
        assert outcome == b"sent" or outcome.startswith(b"error:"), outcome
        connection.settimeout(1)
        try:
            leaked = connection.recv(5)
        except socket.timeout:
            leaked = None
        assert leaked in (None, b""), f"established raw flow survived revocation/expiry: {leaked!r}"
        if outcome == b"sent":
            parent.sendall(b"x")
        connection.close()
    finally:
        parent.close()
        server.close()
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


def held_udp_flow(port, stop_grant):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((DESTINATION, port))
    server.settimeout(5)
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            os.setgid(HERMES_UID)
            os.setuid(HERMES_UID)
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.connect((DESTINATION, port))
            client.settimeout(5)
            client.send(b"before")
            assert client.recv(3) == b"ack"
            child.sendall(b"ready")
            child.recv(1)
            client.send(b"after")
            child.sendall(b"sent")
            child.recv(1)
            client.close()
        except Exception as exc:
            child.sendall(f"error:{type(exc).__name__}".encode())
        finally:
            os._exit(0)
    child.close()
    try:
        data, address = server.recvfrom(6)
        assert data == b"before"
        server.sendto(b"ack", address)  # Conntrack now sees a reply.
        assert parent.recv(5) == b"ready"
        stop_grant()
        parent.sendall(b"x")
        parent.settimeout(5)
        outcome = parent.recv(64)
        assert outcome == b"sent" or outcome.startswith(b"error:"), outcome
        server.settimeout(1)
        try:
            leaked = server.recv(5)
        except socket.timeout:
            leaked = None
        assert leaked is None, f"established raw UDP flow survived expiry: {leaked!r}"
        if outcome == b"sent":
            parent.sendall(b"x")
    finally:
        parent.close()
        server.close()
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


run("ip", "link", "set", "lo", "up")
run("ip", "address", "add", f"{DESTINATION}/32", "dev", "lo")
run("iptables", "-N", "ufw-before-output")
run("iptables", "-N", "ufw-user-output")
run("iptables", "-A", "OUTPUT", "-j", "ufw-before-output")
run("iptables", "-A", "OUTPUT", "-j", "ufw-user-output")
run("iptables", "-A", "ufw-before-output", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
run("iptables", "-A", "ufw-user-output", "-d", "192.168.0.0/16", "-j", "DROP")

firewall = ExactEgress(HERMES_UID, PROXY_UID)
for port, scenario in ((2222, "revoke"), (2223, "expiry")):
    request_id = str(uuid.uuid4())
    now = time.time()
    expiry = int(now) + 4
    firewall.ensure_grant("raw", DESTINATION, port, "tcp", request_id, expiry, now)
    if scenario == "revoke":
        stop = lambda: firewall.revoke("raw", DESTINATION, port, "tcp", request_id, expiry)
    else:
        stop = lambda: time.sleep(max(0, expiry - time.time()) + 1)
    held_flow(port, stop)
    if scenario == "expiry":
        firewall.revoke("raw", DESTINATION, port, "tcp", request_id, expiry)

request_id = str(uuid.uuid4())
now = time.time()
expiry = int(now) + 4
firewall.ensure_grant("raw", DESTINATION, 2224, "udp", request_id, expiry, now)
held_udp_flow(2224, lambda: time.sleep(max(0, expiry - time.time()) + 1))
firewall.revoke("raw", DESTINATION, 2224, "udp", request_id, expiry)

print("established raw TCP/UDP is blocked after revoke and independent expiry: OK")
