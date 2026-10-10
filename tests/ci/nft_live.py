"""Exercise the dedicated nftables kill-switch table in a disposable net namespace."""

from __future__ import annotations

import subprocess

from deadbolt.actions import EmergencyAction


def main() -> None:
    action = EmergencyAction(12345)
    assert not action.enabled()
    try:
        action._install_block()
        assert action.enabled()
        action._install_block()
        listed = subprocess.run(["/usr/sbin/nft", "list", "table", "inet",
                                 "deadbolt_killswitch"], check=True, text=True,
                                capture_output=True, timeout=10).stdout
        assert "meta skuid 12345 drop" in listed
    finally:
        subprocess.run(["/usr/sbin/nft", "delete", "table", "inet", "deadbolt_killswitch"],
                       check=False, capture_output=True, timeout=10)
    assert not action.enabled()
    print("real nftables emergency block apply and removal passed")


if __name__ == "__main__":
    main()
