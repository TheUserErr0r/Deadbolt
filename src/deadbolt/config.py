"""Root-owned configuration and policy validation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import tomllib


NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class ConfigurationError(ValueError):
    pass


def _absolute(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ConfigurationError(f"{field} must be an absolute path")
    return Path(value)


def _cidr(value: object, field: str) -> str:
    if value == "any":
        return "any"
    if not isinstance(value, str):
        raise ConfigurationError(f"{field} must be a CIDR or 'any'")
    try:
        return str(ipaddress.ip_network(value, strict=True))
    except ValueError as exc:
        raise ConfigurationError(f"{field} must be a canonical CIDR") from exc


def _port(value: object) -> str:
    if type(value) is int and 1 <= value <= 65535:
        return str(value)
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}:[0-9]{1,5}", value):
        lo, hi = map(int, value.split(":"))
        if 1 <= lo < hi <= 65535 and hi - lo <= 15:
            return value
    raise ConfigurationError("port must be a numeric port or range of at most 16 ports")


@dataclass(frozen=True)
class FirewallProfile:
    name: str
    direction: str
    protocol: str
    source: str
    destination: str
    port: str
    interface: str | None
    max_ttl_seconds: int

    @classmethod
    def from_mapping(cls, name: str, data: object) -> FirewallProfile:
        if not NAME.fullmatch(name) or not isinstance(data, dict):
            raise ConfigurationError("invalid firewall profile")
        allowed = {"direction", "protocol", "source", "destination", "port", "interface", "max_ttl_seconds"}
        if set(data) - allowed or allowed.difference(data) - {"interface"}:
            raise ConfigurationError(f"invalid fields in profile {name}")
        direction, protocol = data["direction"], data["protocol"]
        if direction not in ("in", "out") or protocol not in ("tcp", "udp"):
            raise ConfigurationError(f"invalid direction/protocol in {name}")
        interface = data.get("interface")
        if interface is not None and (not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface)):
            raise ConfigurationError(f"invalid interface in {name}")
        ttl = data["max_ttl_seconds"]
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ConfigurationError(f"invalid max_ttl_seconds in {name}")
        source = _cidr(data["source"], "source")
        destination = _cidr(data["destination"], "destination")
        remote = source if direction == "in" else destination
        if remote == "any" or ipaddress.ip_network(remote).prefixlen == 0:
            raise ConfigurationError(f"profile {name} must limit its remote network")
        return cls(name, direction, protocol, source, destination, _port(data["port"]), interface, ttl)


@dataclass(frozen=True)
class Policy:
    firewall_profiles: dict[str, FirewallProfile]

    @classmethod
    def load(cls, path: Path) -> Policy:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        if set(raw) != {"firewall_profiles"} or not isinstance(raw["firewall_profiles"], dict):
            raise ConfigurationError("profiles.toml requires only [firewall_profiles]")
        return cls({name: FirewallProfile.from_mapping(name, value)
                    for name, value in raw["firewall_profiles"].items()})


@dataclass(frozen=True)
class ExecutorConfig:
    state_path: Path
    audit_path: Path
    bot_socket: Path
    profiles_path: Path
    bot_user: str
    hermes_user: str
    discord_user_id: str
    discord_guild_id: str
    discord_channel_id: str
    pending_ttl_seconds: int = 600
    default_ttl_seconds: int = 1800
    max_ttl_seconds: int = 3600

    @classmethod
    def load(cls, path: Path) -> ExecutorConfig:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        if set(raw) != {"executor", "discord"}:
            raise ConfigurationError("executor.toml requires [executor] and [discord]")
        executor, discord = raw["executor"], raw["discord"]
        required = {"state_path", "audit_path", "bot_socket", "profiles_path", "bot_user", "hermes_user"}
        if set(executor) != required or set(discord) != {"user_id", "guild_id", "channel_id"}:
            raise ConfigurationError("unexpected or missing executor configuration fields")
        ids = [discord[key] for key in ("user_id", "guild_id", "channel_id")]
        if any(not isinstance(value, str) or not value.isdecimal() for value in ids):
            raise ConfigurationError("Discord IDs must be decimal strings")
        if executor["bot_user"] != "deadbolt":
            raise ConfigurationError("bot_user must be the dedicated deadbolt account")
        if executor["hermes_user"] != "hermes":
            raise ConfigurationError("hermes_user must be hermes")
        return cls(_absolute(executor["state_path"], "state_path"),
                   _absolute(executor["audit_path"], "audit_path"),
                   _absolute(executor["bot_socket"], "bot_socket"),
                   _absolute(executor["profiles_path"], "profiles_path"),
                   executor["bot_user"], executor["hermes_user"], *ids)


def resolve_action(action: str, profile_name: str, reason: str, requested_ttl: int | None,
                   policy: Policy, config: ExecutorConfig) -> dict[str, object]:
    if action != "firewall_profile":
        raise ConfigurationError("action is disabled or unknown")
    profile = policy.firewall_profiles.get(profile_name)
    if profile is None:
        raise ConfigurationError("profile is not allowed")
    if (not isinstance(reason, str) or not 1 <= len(reason) <= 500 or reason != reason.strip()
            or any(not ch.isprintable() for ch in reason)):
        raise ConfigurationError("reason must be 1-500 printable characters")
    if requested_ttl is not None and (type(requested_ttl) is not int or requested_ttl < 1):
        raise ConfigurationError("ttl_seconds must be a positive integer")
    ttl = min(requested_ttl or config.default_ttl_seconds, profile.max_ttl_seconds, config.max_ttl_seconds)
    return {
        "action": action, "profile": profile.name, "direction": profile.direction,
        "protocol": profile.protocol, "source": profile.source,
        "destination": profile.destination, "port": profile.port,
        "interface": profile.interface, "reason": reason, "ttl_seconds": ttl,
    }


def describe_action(action: dict[str, object]) -> str:
    interface = f" on {action['interface']}" if action["interface"] else ""
    return (f"UFW allow {action['direction']}{interface}: {action['protocol']} "
            f"from {action['source']} to {action['destination']} port {action['port']}\n"
            f"Profile: {action['profile']}\nReason: {action['reason']}\n"
            f"Active TTL: {action['ttl_seconds']} seconds")
