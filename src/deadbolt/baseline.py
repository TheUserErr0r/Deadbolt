"""Fixed durable host egress contract, separate from approval grants."""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import stat
import tomllib

from deadbolt.actions import ActionError, UfwAction


class BaselineError(ValueError):
    pass


def _host_ip(value: object) -> str:
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise BaselineError("baseline endpoint must be a literal IP") from exc
    if str(address) != value or address.is_loopback or address.is_link_local or address.is_multicast:
        raise BaselineError("baseline endpoint must be canonical and nonlocal")
    return str(address)


def load(path: Path) -> list[tuple[str, list[str]]]:
    info = path.lstat()
    parent = path.parent.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022):
        raise BaselineError("baseline config must be root-owned and nonwritable by other users")
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    if set(raw) != {"baseline"} or not isinstance(raw["baseline"], dict) or set(raw["baseline"]) != {"dns_ip", "argus_ip"}:
        raise BaselineError("baseline requires only dns_ip and argus_ip")
    dns, argus = _host_ip(raw["baseline"]["dns_ip"]), _host_ip(raw["baseline"]["argus_ip"])
    return [("dns-udp", ["allow", "out", "to", dns, "port", "53", "proto", "udp"]),
            ("dns-tcp", ["allow", "out", "to", dns, "port", "53", "proto", "tcp"]),
            ("http", ["allow", "out", "to", "any", "port", "80", "proto", "tcp"]),
            ("https", ["allow", "out", "to", "any", "port", "443", "proto", "tcp"]),
            ("wazuh-events", ["allow", "out", "to", argus, "port", "1514", "proto", "tcp"]),
            ("wazuh-enroll", ["allow", "out", "to", argus, "port", "1515", "proto", "tcp"]),
            ("loki", ["allow", "out", "to", argus, "port", "3100", "proto", "tcp"])]


def ensure(rules: list[tuple[str, list[str]]], *, apply: bool,
           ufw: UfwAction | None = None) -> list[str]:
    action = ufw or UfwAction()
    action._ensure_active()
    missing: list[str] = []
    for name, rule in rules:
        present = [item for item, _comment in action._added() if item == rule]
        if present:
            continue
        missing.append(name)
        if apply:
            action._run([*rule, "comment", f"deadbolt-baseline:{name}"])
            if not any(item == rule for item, _comment in action._added()):
                raise ActionError(f"baseline {name} could not be verified")
    return missing


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify or install fixed durable Deadbolt baseline egress")
    parser.add_argument("operation", choices=("verify", "apply"))
    parser.add_argument("--config", type=Path, default=Path("/etc/deadbolt/baseline-egress.toml"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("baseline management requires root")
    missing = ensure(load(args.config), apply=args.operation == "apply")
    if args.operation == "verify" and missing:
        raise SystemExit("missing baseline rules: " + ", ".join(missing))
    print("baseline egress verified")


if __name__ == "__main__":
    main()
