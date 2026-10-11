"""Run only in a network-disabled NET_ADMIN container."""
import subprocess
import time
import uuid

from deadbolt.broker_firewall import BrokerFirewall


def run(*argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)


run("/usr/sbin/iptables", "-N", "ufw-before-output")
run("/usr/sbin/iptables", "-N", "ufw-user-output")
run("/usr/sbin/ip6tables", "-N", "ufw-before-output")
run("/usr/sbin/ip6tables", "-N", "ufw-user-output")
action = BrokerFirewall(104)
request_id = str(uuid.uuid4())
now = time.time()
expiry = int(now) + 60
action.ensure_guard()
grant = action.ensure_grant("192.168.1.205", request_id, expiry, now)
assert grant["uid"] == 104
action.assert_grant("192.168.1.205", request_id, expiry)
action.ensure_grant("192.168.1.205", request_id, expiry, now)
run("/usr/sbin/iptables", "-F", "ufw-user-output")
action.ensure_grant("192.168.1.205", request_id, expiry, now)
action.revoke("192.168.1.205", request_id, expiry)
action.revoke("192.168.1.205", request_id, expiry)
print("broker two-layer nftables/UFW grant, reinstall, revoke: OK")
