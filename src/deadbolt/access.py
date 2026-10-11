"""Root-owned policy for exact, short-lived outbound access requests."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import hashlib
import json
import re
import socket
from typing import Callable


class AccessError(ValueError):
    pass


HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
PROFILE_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
SENSITIVE = re.compile(r"(?i)(?:password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]")
SHELL_META = re.compile(r"[;&|`$<>\\]")
MAX_ADDRESSES = 8
MAX_ARGC = 16
MAX_ARG_BYTES = 256
MAX_COMMAND_BYTES = 2048


def destination(value: object) -> tuple[str, str]:
    """Return (canonical destination, kind), rejecting ambiguous spellings."""
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or not value.isascii():
        raise AccessError("destination must be an ASCII hostname or literal IP")
    if value != value.strip() or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise AccessError("invalid destination characters")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        if value != address.compressed:
            raise AccessError("IP address must be canonical")
        if getattr(address, "ipv4_mapped", None) is not None:
            raise AccessError("mapped IPv6 addresses are ambiguous")
        if not address.is_global and not address.is_private:
            raise AccessError("special-use destination is not allowed")
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise AccessError("special-use destination is not allowed")
        return str(address), "ip"
    name = value.lower()
    if (name.endswith(".") or "." not in name or name.startswith("localhost.")
            or name.startswith("xn--")
            or any(label.startswith("xn--") or not HOST_LABEL.fullmatch(label)
                   for label in name.split("."))
            or name in {"localhost", "localhost.localdomain"}
            or all(part.isdecimal() for part in name.split("."))):
        raise AccessError("invalid DNS hostname")
    return name, "dns"


def purpose(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 200 or value != value.strip()
            or not value.isascii() or any(ord(c) < 32 or ord(c) > 126 for c in value)
            or SENSITIVE.search(value) or "://" in value):
        raise AccessError("purpose must be short, printable, and secret-free")
    return value


def command_argv(value: object, *, allow_sensitive: bool = False) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARGC:
        raise AccessError("command must be a bounded argv array")
    total = 0
    for item in value:
        if (not isinstance(item, str) or not item or not item.isascii()
                or len(item.encode()) > MAX_ARG_BYTES
                or any(ord(c) < 32 or ord(c) > 126 for c in item)
                or (not allow_sensitive and (SENSITIVE.search(item) or "://" in item))
                or SHELL_META.search(item)):
            raise AccessError("invalid or sensitive command argument")
        total += len(item.encode())
    if total > MAX_COMMAND_BYTES or re.match(r"[A-Za-z_][A-Za-z0-9_]*=", value[0]):
        raise AccessError("command exceeds limits or begins with an environment assignment")
    if value[0].startswith("-") or "/" in value[0] or value[0] in {"sh", "bash", "zsh", "env", "sudo", "su"}:
        raise AccessError("command executable is not permitted")
    return value[:]


@dataclass(frozen=True)
class AccessProfile:
    name: str
    direction: str
    protocol: str
    ports: tuple[int, ...]
    max_ttl_seconds: int
    target_types: frozenset[str]
    allowed_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allow_public: bool
    operator_approval: bool
    audited_execution: bool
    max_commands: int = 0
    audit_output: str = "metadata"
    ssh_user: str | None = None
    ssh_key: str | None = None
    known_hosts: str | None = None
    remote_commands: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, name: str, raw: object) -> "AccessProfile":
        if not isinstance(name, str) or not PROFILE_NAME.fullmatch(name) or not isinstance(raw, dict):
            raise AccessError("invalid access profile")
        required = {"direction", "protocol", "ports", "max_ttl_seconds", "target_types",
                    "allowed_cidrs", "allow_public", "operator_approval", "audited_execution"}
        optional = {"ssh_user", "ssh_key", "known_hosts", "remote_commands", "audit_output"}
        required |= {"max_commands"}
        if set(raw) - required - optional or required - set(raw):
            raise AccessError("unexpected or missing access profile fields")
        if raw["direction"] != "out" or raw["protocol"] not in ("tcp", "udp"):
            raise AccessError("access profiles must be outbound TCP or UDP")
        ports = raw["ports"]
        if (not isinstance(ports, list) or not 1 <= len(ports) <= 8
                or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
                or len(set(ports)) != len(ports)):
            raise AccessError("ports must be a small exact set")
        ttl = raw["max_ttl_seconds"]
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise AccessError("invalid access TTL limit")
        types = raw["target_types"]
        if (not isinstance(types, list) or not types or
                any(not isinstance(item, str) for item in types) or
                len(set(types)) != len(types) or not set(types) <= {"ip", "dns"}):
            raise AccessError("invalid target types")
        values = raw["allowed_cidrs"]
        if not isinstance(values, list) or len(values) > 32:
            raise AccessError("invalid CIDR policy")
        networks = []
        for value in values:
            if not isinstance(value, str):
                raise AccessError("invalid CIDR policy")
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise AccessError("invalid CIDR policy") from exc
            if str(network) != value or network.prefixlen == 0:
                raise AccessError("CIDR policy must be canonical and bounded")
            networks.append(network)
        for flag in ("allow_public", "operator_approval", "audited_execution"):
            if type(raw[flag]) is not bool:
                raise AccessError("invalid access profile flag")
        if not raw["operator_approval"]:
            raise AccessError("operator approval is mandatory in this version")
        if not networks and not raw["allow_public"]:
            raise AccessError("access profile has no permitted destinations")
        ssh = raw["audited_execution"]
        extras = {field: raw.get(field) for field in ("ssh_user", "ssh_key", "known_hosts")}
        commands = raw.get("remote_commands", [])
        if ssh:
            if (raw["protocol"] != "tcp" or ports != [22]
                    or any(not isinstance(v, str) for v in extras.values())
                    or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", extras["ssh_user"] or "")
                    or not extras["ssh_key"].startswith("/etc/deadbolt/keys/")
                    or not extras["known_hosts"].startswith("/etc/deadbolt/known-hosts/")
                    or any(".." in v.split("/") for v in
                           (extras["ssh_key"], extras["known_hosts"]))
                    or not isinstance(commands, list) or not 1 <= len(commands) <= 16
                    or any(not isinstance(c, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", c)
                           for c in commands)):
                raise AccessError("invalid SSH profile contract")
        else:
            raise AccessError("only audited SSH family profiles are enabled in this version")
        maximum = raw.get("max_commands")
        audit_output = raw.get("audit_output", "metadata")
        if type(maximum) is not int or not 1 <= maximum <= 100:
            raise AccessError("SSH profile requires a command limit from 1 to 100")
        if audit_output not in ("metadata", "full"):
            raise AccessError("invalid SSH output audit mode")
        if any(port in (80, 443) for port in ports):
            raise AccessError("baseline HTTP/HTTPS ports cannot be approval profiles")
        return cls(name, "out", raw["protocol"], tuple(sorted(ports)), ttl,
                   frozenset(types), tuple(networks), raw["allow_public"], True, ssh,
                   maximum, audit_output, extras["ssh_user"], extras["ssh_key"],
                   extras["known_hosts"], tuple(commands))

    def permits(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
        return any(ip in net for net in self.allowed_cidrs) or (self.allow_public and ip.is_global)


Resolver = Callable[[str], list[str]]


def resolve_host(name: str) -> list[str]:
    try:
        results = socket.getaddrinfo(name, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AccessError("DNS resolution failed") from exc
    addresses = sorted({str(ipaddress.ip_address(item[4][0])) for item in results})
    if not addresses or len(addresses) > MAX_ADDRESSES:
        raise AccessError("DNS answer is empty or too large")
    return addresses


def pin_destination(value: object, profile: AccessProfile, resolver: Resolver = resolve_host) -> tuple[str, list[str]]:
    name, kind = destination(value)
    if kind not in profile.target_types:
        raise AccessError("target type is not permitted")
    addresses = [name] if kind == "ip" else resolver(name)
    if not addresses or len(addresses) > MAX_ADDRESSES or len(set(addresses)) != len(addresses):
        raise AccessError("invalid DNS answer")
    for address in addresses:
        try:
            if str(ipaddress.ip_address(address)) != address or not profile.permits(address):
                raise AccessError("resolved address is outside profile policy")
        except ValueError as exc:
            raise AccessError("invalid resolved address") from exc
    return name, sorted(addresses)


def canonical_access(profile: AccessProfile, target: object, why: object, ttl: object,
                     argv: object = None, resolver: Resolver = resolve_host) -> dict[str, object]:
    if type(ttl) is not int or not 1 <= ttl <= profile.max_ttl_seconds:
        raise AccessError("requested TTL exceeds the profile limit")
    name, addresses = pin_destination(target, profile, resolver)
    if len(addresses) * len(profile.ports) > 16:
        raise AccessError("resolution requires too many exact firewall rules")
    if len(addresses) != 1:
        raise AccessError("SSH execution requires one unambiguous pinned IP")
    command = command_argv(argv, allow_sensitive=profile.audit_output == "full")
    if command[0] not in profile.remote_commands:
        raise AccessError("command is not in the root-owned SSH allow-list")
    safe_purpose = purpose(why)
    return {"action": "access_grant", "profile": profile.name, "direction": profile.direction,
            "protocol": profile.protocol, "ports": list(profile.ports), "destination": name,
            "pinned_ips": addresses, "purpose": safe_purpose, "reason": safe_purpose,
            "ttl_seconds": ttl, "audited_execution": profile.audited_execution,
            "initial_command": command, "max_commands": profile.max_commands,
            "audit_output": profile.audit_output,
            "ssh_user": profile.ssh_user, "ssh_key": profile.ssh_key,
            "known_hosts": profile.known_hosts,
            "remote_commands": list(profile.remote_commands)}


def describe_access(record: dict[str, object]) -> str:
    command = record["initial_command"]
    summary = command_summary(command)
    return (f"Parameterized access profile: {record['profile']}\n"
            f"Destination: {record['destination']}\n"
            f"Resolved pinned IPs: {', '.join(record['pinned_ips'])}\n"
            f"Protocol: {record['protocol']}\nPorts: {', '.join(map(str, record['ports']))}\n"
            f"SSH user: {record['ssh_user']}\nActive TTL: {record['ttl_seconds']} seconds\n"
            f"Command limit: {record['max_commands']}\nPurpose: {record['purpose']}\n"
            f"First command: {summary['name']} ({summary['argument_count']} arguments; "
            f"argv SHA-256: {summary['argv_sha256']})\nFurther allowed commands need no new approval. "
            "Each is validated and audited separately.")


def command_summary(argv: list[str]) -> dict[str, object]:
    return {"name": argv[0], "argument_count": len(argv) - 1,
            "argv_sha256": hashlib.sha256(json.dumps(argv, ensure_ascii=True,
                separators=(",", ":")).encode()).hexdigest()}
