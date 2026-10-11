"""Install the broker-wide SSH deny before the executor accepts requests."""

from __future__ import annotations

import argparse
from pathlib import Path
import pwd

from deadbolt.broker_firewall import BrokerFirewall
from deadbolt.config import ExecutorConfig, Policy


def main() -> None:
    parser = argparse.ArgumentParser(description="Restore the Deadbolt SSH broker guard")
    parser.add_argument("--config", type=Path, default=Path("/etc/deadbolt/executor.toml"))
    args = parser.parse_args()
    config = ExecutorConfig.load(args.config)
    policy = Policy.load(config.profiles_path)
    if not (policy.access_profiles or {}):
        return
    uid = pwd.getpwnam("deadbolt-ssh").pw_uid
    firewall = BrokerFirewall(uid)
    firewall.ensure_guard()
    firewall._check_static_bypass()


if __name__ == "__main__":
    main()
