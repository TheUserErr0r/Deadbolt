"""Prestart fail-closed guard for the SSH proxy service account."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd

from deadbolt.config import ExecutorConfig, Policy
from deadbolt.outbound_firewall import ExactEgress
from deadbolt.store import Store


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/etc/deadbolt/executor.toml"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("outbound guard must run as root")
    config = ExecutorConfig.load(args.config)
    policy = Policy.load(config.profiles_path)
    store = Store(config.state_path, config.audit_path, config.pending_ttl_seconds)
    try:
        if policy.outbound_access.enabled or store.active_outbound_rows():
            ExactEgress(pwd.getpwnam(config.hermes_user).pw_uid,
                        pwd.getpwnam("deadbolt-ssh-proxy").pw_uid).ensure_guard()
    finally:
        store.close()
