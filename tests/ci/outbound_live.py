"""Exercise exact SSH-proxy and raw grants in a network-disabled container."""

import subprocess
import time
import uuid

from deadbolt.outbound_firewall import ExactEgress


def run(*argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)


for binary in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
    run(binary, "-N", "ufw-before-output")
    run(binary, "-N", "ufw-user-output")
run("/usr/sbin/iptables", "-A", "ufw-user-output", "-d", "192.168.0.0/16", "-j", "DROP")
run("/usr/sbin/iptables", "-A", "ufw-before-output", "-m", "owner", "--uid-owner", "1001",
    "-p", "tcp", "--dport", "22", "-j", "DROP")

firewall = ExactEgress(1001, 1002)
rid = str(uuid.uuid4())
now = time.time()
expiry = int(now) + 90
firewall.ensure_guard()
grant = firewall.ensure_grant("ssh", "192.168.1.205", 22, "tcp", rid, expiry, now)
assert grant["uid"] == 1002
firewall.assert_grant("ssh", "192.168.1.205", 22, "tcp", rid, expiry)
run("/usr/sbin/iptables", "-F", "ufw-user-output")
run("/usr/sbin/iptables", "-A", "ufw-user-output", "-d", "192.168.0.0/16", "-j", "DROP")
firewall.ensure_grant("ssh", "192.168.1.205", 22, "tcp", rid, expiry, now)
firewall.revoke("ssh", "192.168.1.205", 22, "tcp", rid, expiry)
firewall.revoke("ssh", "192.168.1.205", 22, "tcp", rid, expiry)

raw_id = str(uuid.uuid4())
firewall.ensure_grant("raw", "192.168.1.205", 22, "tcp", raw_id, expiry, now)
firewall.assert_grant("raw", "192.168.1.205", 22, "tcp", raw_id, expiry)
firewall.revoke("raw", "192.168.1.205", 22, "tcp", raw_id, expiry)
print("exact outbound SSH-proxy and raw grants, order, reload, revoke: OK")
