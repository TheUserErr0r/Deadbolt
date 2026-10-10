"""Restore a persisted emergency block before the proxy may start at boot."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import time

from deadbolt.actions import EmergencyAction
from deadbolt.config import ExecutorConfig
from deadbolt.executor import _secure_root_path
from deadbolt.store import Store


def restore(config: ExecutorConfig) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("emergency restore must run as root")
    os.umask(0o077)
    for path in (config.state_path, config.audit_path, config.profiles_path):
        _secure_root_path(path)
    store = Store(config.state_path, config.audit_path, config.pending_ttl_seconds)
    try:
        state = store.emergency_state()
        if state["state"] != "inactive":
            action = EmergencyAction(pwd.getpwnam(config.hermes_user).pw_uid)
            try:
                action.enforce(tuple(state["workload_units"]))
            except Exception:
                store.emergency_event("emergency_boot_restore_failed", time.time(),
                                      error="emergency enforcement failed")
                store.flush_audit()
                raise
            if state["state"] != "active":
                store.emergency_transition((state["state"],), "active",
                    "emergency_boot_restored", time.time())
            else:
                store.emergency_event("emergency_boot_reenforced", time.time())
            store.flush_audit()
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Restore a persisted Deadbolt emergency stop")
    parser.add_argument("--config", type=Path, default=Path("/etc/deadbolt/executor.toml"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("emergency restore must run as root")
    _secure_root_path(args.config)
    restore(ExecutorConfig.load(args.config))


if __name__ == "__main__":
    main()
