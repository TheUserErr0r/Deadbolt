"""Root-owned boundaries and canonical requests for temporary inbound listeners."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

from deadbolt.access import purpose as validated_purpose


class IngressError(ValueError):
    pass


DEFAULT_MAX_TTL_SECONDS = 3600
HARD_MAX_TTL_SECONDS = 24 * 3600
DEFAULT_MAX_PORT_WIDTH = 5
HARD_MAX_PORT_WIDTH = 16
MAX_SOURCE_ADDRESSES = 256
PRIVATE_LAN = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def _network(value: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(value, str) or not value.isascii() or value != value.strip():
        raise IngressError("source must be a canonical literal IP or CIDR")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=True)
            if str(network) != value:
                raise ValueError
        else:
            address = ipaddress.ip_address(value)
            if address.compressed != value:
                raise ValueError
            network = ipaddress.ip_network(f"{value}/{address.max_prefixlen}")
    except ValueError as exc:
        raise IngressError("source must be a canonical literal IP or CIDR") from exc
    address = network.network_address
    if (network.num_addresses > MAX_SOURCE_ADDRESSES or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_unspecified
            or getattr(address, "ipv4_mapped", None) is not None):
        raise IngressError("source network is broad or special-use")
    return network


def _local_ip(value: object) -> str:
    if not isinstance(value, str) or not value.isascii() or value != value.strip():
        raise IngressError("local destination must be a canonical private LAN IP")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise IngressError("local destination must be a canonical private LAN IP") from exc
    if (address.compressed != value or getattr(address, "ipv4_mapped", None) is not None
            or not any(address in network for network in PRIVATE_LAN)):
        raise IngressError("local destination must be a canonical private LAN IP")
    return value


@dataclass(frozen=True)
class IngressPolicy:
    enabled: bool = False
    max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS
    max_port_width: int = DEFAULT_MAX_PORT_WIDTH
    allowed_source_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @classmethod
    def parse(cls, raw: object) -> "IngressPolicy":
        if raw is None:
            return cls()
        if not isinstance(raw, dict) or set(raw) - {
                "enabled", "max_ttl_seconds", "max_port_width", "allowed_source_cidrs"}:
            raise IngressError("invalid ingress policy fields")
        enabled = raw.get("enabled", False)
        ttl = raw.get("max_ttl_seconds", DEFAULT_MAX_TTL_SECONDS)
        width = raw.get("max_port_width", DEFAULT_MAX_PORT_WIDTH)
        sources = raw.get("allowed_source_cidrs", [])
        if type(enabled) is not bool or type(ttl) is not int or not 1 <= ttl <= HARD_MAX_TTL_SECONDS:
            raise IngressError("invalid ingress TTL policy")
        if type(width) is not int or not 1 <= width <= HARD_MAX_PORT_WIDTH:
            raise IngressError("invalid ingress port-width policy")
        if not isinstance(sources, list) or len(sources) > 32 or len(set(map(str, sources))) != len(sources):
            raise IngressError("invalid ingress source policy")
        networks = tuple(_network(item) for item in sources)
        if enabled and not networks:
            raise IngressError("enabled ingress policy needs bounded source CIDRs")
        return cls(enabled, ttl, width, networks)


def canonical_ingress(policy: IngressPolicy, *, protocol: object, source_ip: object,
                      local_ip: object, port_start: object, port_end: object,
                      ttl_seconds: object, reason: object) -> dict[str, Any]:
    if not policy.enabled:
        raise IngressError("ingress is disabled by root policy")
    if protocol not in ("tcp", "udp"):
        raise IngressError("ingress protocol must be explicitly tcp or udp")
    source = _network(source_ip)
    local = _local_ip(local_ip)
    if source.version != ipaddress.ip_address(local).version:
        raise IngressError("source and local destination address families differ")
    if not any(source.subnet_of(boundary) for boundary in policy.allowed_source_cidrs):
        raise IngressError("source is outside the root-owned ingress policy")
    if (type(port_start) is not int or type(port_end) is not int
            or not 1024 <= port_start <= port_end <= 65535
            or port_end - port_start + 1 > policy.max_port_width):
        raise IngressError("ingress port range exceeds the root-owned limit")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= policy.max_ttl_seconds:
        raise IngressError("ingress TTL exceeds the root-owned limit")
    try:
        why = validated_purpose(reason)
    except ValueError as exc:
        raise IngressError(str(exc)) from exc
    return {"action": "ingress_access", "profile": "ingress", "direction": "in",
            "protocol": protocol, "source": str(source), "local_ip": local,
            "port_start": port_start, "port_end": port_end,
            "ttl_seconds": ttl_seconds, "reason": why}


def describe_ingress(record: dict[str, Any]) -> str:
    ports = (str(record["port_start"]) if record["port_start"] == record["port_end"]
             else f'{record["port_start"]}-{record["port_end"]}')
    return ("Temporary inbound listener grant\n"
            f"Source: {record['source']}\n"
            f"Hermes LAN destination: {record['local_ip']}\n"
            f"Protocol: {record['protocol'].upper()}\n"
            f"Local port(s): {ports}\n"
            f"Duration: {record['ttl_seconds']} seconds\n"
            f"Reason: {record['reason']}\n"
            "New target-initiated traffic only; outbound access is unchanged.")
