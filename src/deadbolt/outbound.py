"""Root-owned policy and canonical requests for approved outbound IP access."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Any

from deadbolt.access import purpose as validated_purpose


class OutboundError(ValueError):
    pass


MAX_OUTBOUND_TTL_SECONDS = 24 * 3600
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


def literal_ip(value: object) -> str:
    if not isinstance(value, str) or not value.isascii() or value != value.strip():
        raise OutboundError("destination must be a canonical literal IP")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise OutboundError("destination must be a canonical literal IP") from exc
    if (value != address.compressed or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_unspecified
            or getattr(address, "ipv4_mapped", None) is not None):
        raise OutboundError("destination is ambiguous or special-use")
    return value


def exact_port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise OutboundError("port must be one integer from 1 to 65535")
    return value


def _fixed_path(value: object, prefix: str) -> str:
    if (not isinstance(value, str) or not value.startswith(prefix)
            or ".." in Path(value).parts or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)):
        raise OutboundError("invalid root-owned SSH proxy path")
    return value


@dataclass(frozen=True)
class SSHTarget:
    ip: str
    port: int
    user: str
    key: str
    host_fingerprint: str

    @classmethod
    def parse(cls, raw: object) -> "SSHTarget":
        if not isinstance(raw, dict) or set(raw) != {"ip", "port", "user", "key", "host_fingerprint"}:
            raise OutboundError("invalid SSH target configuration")
        ip = literal_ip(raw["ip"])
        port = exact_port(raw["port"])
        user = raw["user"]
        fingerprint = raw["host_fingerprint"]
        if (not isinstance(user, str) or not USER.fullmatch(user)
                or not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint)):
            raise OutboundError("invalid SSH target user or host-key fingerprint")
        return cls(ip, port, user, _fixed_path(raw["key"], "/etc/deadbolt-ssh-proxy/keys/"), fingerprint)


@dataclass(frozen=True)
class OutboundPolicy:
    enabled: bool = False
    max_ttl_seconds: int = MAX_OUTBOUND_TTL_SECONDS
    allowed_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    allow_public: bool = False
    proxy_port: int = 10022
    proxy_host_key: str = ""
    hermes_client_key: str = ""
    spool_dir: str = ""
    ssh_targets: tuple[SSHTarget, ...] = ()

    @classmethod
    def parse(cls, raw: object) -> "OutboundPolicy":
        if raw is None:
            return cls()
        if not isinstance(raw, dict) or set(raw) != {
            "enabled", "max_ttl_seconds", "allowed_cidrs", "allow_public", "proxy_port",
            "proxy_host_key", "hermes_client_key", "spool_dir", "ssh_targets"
        }:
            raise OutboundError("invalid outbound access policy fields")
        if type(raw["enabled"]) is not bool or type(raw["allow_public"]) is not bool:
            raise OutboundError("invalid outbound access policy flags")
        ttl = raw["max_ttl_seconds"]
        if type(ttl) is not int or not 1 <= ttl <= MAX_OUTBOUND_TTL_SECONDS:
            raise OutboundError("outbound TTL maximum must be at most 24 hours")
        cidrs = raw["allowed_cidrs"]
        if not isinstance(cidrs, list) or len(cidrs) > 32:
            raise OutboundError("invalid outbound CIDR policy")
        networks = []
        for value in cidrs:
            if not isinstance(value, str):
                raise OutboundError("invalid outbound CIDR")
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise OutboundError("invalid outbound CIDR") from exc
            if str(network) != value or network.prefixlen == 0:
                raise OutboundError("outbound CIDR must be canonical and bounded")
            networks.append(network)
        if raw["enabled"] and not networks and not raw["allow_public"]:
            raise OutboundError("enabled outbound policy has no allowed destination")
        port = exact_port(raw["proxy_port"])
        if port < 1025:
            raise OutboundError("SSH proxy must use an unprivileged loopback port")
        targets_raw = raw["ssh_targets"]
        if not isinstance(targets_raw, list) or len(targets_raw) > 64:
            raise OutboundError("invalid SSH target list")
        targets = tuple(SSHTarget.parse(item) for item in targets_raw)
        if len({(target.ip, target.port) for target in targets}) != len(targets):
            raise OutboundError("duplicate SSH target")
        host_key = _fixed_path(raw["proxy_host_key"], "/etc/deadbolt-ssh-proxy/")
        client_key = _fixed_path(raw["hermes_client_key"], "/etc/deadbolt-ssh-proxy/")
        spool_dir = _fixed_path(raw["spool_dir"], "/var/lib/deadbolt-ssh-proxy/")
        return cls(raw["enabled"], ttl, tuple(networks), raw["allow_public"], port,
                   host_key, client_key, spool_dir, targets)

    def permits(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return (not (address.is_loopback or address.is_link_local or address.is_multicast
                     or address.is_unspecified)
                and (any(address in network for network in self.allowed_cidrs)
                     or self.allow_public and address.is_global))

    def target(self, ip: str, port: int) -> SSHTarget:
        for target in self.ssh_targets:
            if target.ip == ip and target.port == port:
                return target
        raise OutboundError("SSH destination has no root-owned proxy credential and host-key pin")


def canonical_outbound(policy: OutboundPolicy, *, kind: object, destination: object,
                       port: object, ttl_seconds: object, purpose: object,
                       transport: object = None) -> dict[str, Any]:
    if not policy.enabled:
        raise OutboundError("outbound access is disabled by root policy")
    if kind not in ("ssh", "raw"):
        raise OutboundError("kind must explicitly be ssh or raw")
    ip = literal_ip(destination)
    number = exact_port(port)
    if not policy.permits(ip):
        raise OutboundError("destination is outside root-owned policy")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= policy.max_ttl_seconds:
        raise OutboundError("requested TTL exceeds the root-owned maximum")
    try:
        why = validated_purpose(purpose)
    except ValueError as exc:
        raise OutboundError(str(exc)) from exc
    if any(character in why for character in "?#@") or re.search(r"\S+/\S+", why):
        raise OutboundError("purpose must not contain a URL, path, or credential hint")
    if kind == "ssh":
        if transport is not None:
            raise OutboundError("SSH transport is fixed to TCP")
        target = policy.target(ip, number)
        if number != 22:
            # A nonstandard SSH port can be added only with an explicit target credential.
            pass
        target_fields = {"ssh_user": target.user, "ssh_key": target.key,
                         "target_host_fingerprint": target.host_fingerprint}
        transport = "tcp"
    else:
        if transport not in ("tcp", "udp"):
            raise OutboundError("raw transport must explicitly be tcp or udp")
        # Baseline HTTP/HTTPS are already open; a grant cannot make them exact.
        if transport == "tcp" and number in (80, 443):
            raise OutboundError("baseline HTTP/HTTPS cannot be represented as exact raw grants")
        target_fields = {}
    return {"action": "outbound_access", "profile": kind, "kind": kind,
            "destination": ip, "port": number, "transport": transport,
            "ttl_seconds": ttl_seconds, "purpose": why, "reason": why, **target_fields}


def describe_outbound(record: dict[str, Any]) -> str:
    base = (f"Outbound {record['kind'].upper()} access\n"
            f"Exact destination: {record['destination']}:{record['port']}\n"
            f"Transport: {record['transport'].upper()}\n"
            f"Duration: {record['ttl_seconds']} seconds\nPurpose: {record['purpose']}\n")
    if record["kind"] == "ssh":
        return (base + f"Target SSH user: {record['ssh_user']}\n"
                "Hermes connects only to the loopback recording proxy. "
                "Direct Hermes-to-target SSH stays blocked. Interactive input/output "
                "and command requests/output are recorded in restricted evidence.")
    warning = "WARNING: RAW ACCESS IS UNINSPECTED. CONTENTS MAY BE INVISIBLE."
    if record["transport"] == "tcp" and record["port"] == 22:
        warning += " RAW TCP/22 BYPASSES SSH INSPECTION AND RECORDING."
    return base + warning
