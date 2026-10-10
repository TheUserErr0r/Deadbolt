"""Exercise real UFW in a network-isolated disposable container."""

from __future__ import annotations

import subprocess
import uuid

from deadbolt.actions import UfwAction


def ufw(*args: str) -> str:
    return subprocess.run(["/usr/sbin/ufw", *args], check=True, text=True,
                          capture_output=True, timeout=20).stdout


def main() -> None:
    ufw("--force", "enable")
    assert ufw("status").startswith("Status: active\n")
    request = {"action": "firewall_profile", "profile": "test-egress", "direction": "out",
               "protocol": "tcp", "source": "any", "destination": "192.0.2.0/24",
               "port": "22", "interface": None, "reason": "isolated UFW test", "ttl_seconds": 60}
    action = UfwAction()
    intent = action.prepare(request, str(uuid.uuid4()))
    assert intent["mutation"] == "tagged", intent
    try:
        action.apply(request, intent)
        assert intent["tag"] in ufw("show", "added")
    finally:
        action.rollback(request, intent)
    assert intent["tag"] not in ufw("show", "added")
    print("real UFW tagged rule apply and rollback passed")


if __name__ == "__main__":
    main()
