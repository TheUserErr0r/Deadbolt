"""Root-owned configuration and policy validation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import tomllib

from deadbolt.access import AccessProfile, AccessError
from deadbolt.outbound import OutboundPolicy, OutboundError


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
    proxy_body_capture_enabled: bool = False
    body_exclusion_allowed_hosts: tuple[str, ...] = ()
    emergency_workload_units: tuple[str, ...] = ()
    access_profiles: dict[str, AccessProfile] | None = None
    outbound_access: OutboundPolicy = OutboundPolicy()

    @classmethod
    def load(cls, path: Path) -> Policy:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        if not set(raw) <= {"firewall_profiles", "access_profiles", "proxy_body_capture", "body_capture_exclusions", "emergency_stop", "outbound_access"} or not isinstance(raw.get("firewall_profiles"), dict):
            raise ConfigurationError("profiles.toml requires [firewall_profiles]")
        capture = raw.get("proxy_body_capture", {"enabled": False})
        if not isinstance(capture, dict) or set(capture) != {"enabled"} or type(capture["enabled"]) is not bool:
            raise ConfigurationError("proxy_body_capture requires only a boolean enabled field")
        exclusions = raw.get("body_capture_exclusions", {"allowed_hosts": []})
        if not isinstance(exclusions, dict) or set(exclusions) != {"allowed_hosts"}:
            raise ConfigurationError("body_capture_exclusions requires only allowed_hosts")
        allowed = normalize_hosts(exclusions["allowed_hosts"])
        emergency = raw.get("emergency_stop", {"workload_units": []})
        if not isinstance(emergency, dict) or set(emergency) != {"workload_units"}:
            raise ConfigurationError("emergency_stop requires only workload_units")
        units = normalize_workload_units(emergency["workload_units"])
        access_raw = raw.get("access_profiles", {})
        if not isinstance(access_raw, dict):
            raise ConfigurationError("access_profiles must be a table")
        try:
            access = {name: AccessProfile.from_mapping(name, value)
                      for name, value in access_raw.items()}
            outbound = OutboundPolicy.parse(raw.get("outbound_access"))
        except (AccessError, OutboundError) as exc:
            raise ConfigurationError(str(exc)) from exc
        return cls({name: FirewallProfile.from_mapping(name, value)
                    for name, value in raw["firewall_profiles"].items()}, capture["enabled"], allowed, units, access, outbound)


def normalize_hosts(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 64:
        raise ConfigurationError("exclusions must be a list of at most 64 exact DNS hostnames")
    hosts: list[str] = []
    for host in value:
        if (not isinstance(host, str) or not 4 <= len(host) <= 253
                or host.lower() != host or host.endswith(".") or "." not in host
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                       for part in host.split("."))):
            raise ConfigurationError("exclusion must be a normalized exact DNS hostname")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ConfigurationError("IP addresses are not exclusion hostnames")
        if host in hosts:
            raise ConfigurationError("duplicate exclusion hostname")
        hosts.append(host)
    if sum(len(host) + 1 for host in hosts) > 8000:
        raise ConfigurationError("exclusion hostname list is too large")
    return tuple(sorted(hosts))


def normalize_workload_units(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 16:
        raise ConfigurationError("workload_units must be a list of at most 16 services")
    units: list[str] = []
    for unit in value:
        if (not isinstance(unit, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@_.-]{0,100}\.service", unit)
                or unit.startswith("deadbolt") or unit.startswith("alloy")
                or unit == "hermes-tls-proxy.service" or unit in units):
            raise ConfigurationError("invalid emergency workload unit")
        units.append(unit)
    return tuple(sorted(units))


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
    restricted_ssh_audit_path: Path | None = None

    @classmethod
    def load(cls, path: Path) -> ExecutorConfig:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        if set(raw) != {"executor", "discord"}:
            raise ConfigurationError("executor.toml requires [executor] and [discord]")
        executor, discord = raw["executor"], raw["discord"]
        required = {"state_path", "audit_path", "bot_socket", "profiles_path", "bot_user", "hermes_user"}
        if (set(executor) - required - {"restricted_ssh_audit_path"} or required - set(executor)
                or set(discord) != {"user_id", "guild_id", "channel_id"}):
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
                   executor["bot_user"], executor["hermes_user"], *ids,
                   restricted_ssh_audit_path=(_absolute(executor["restricted_ssh_audit_path"],
                       "restricted_ssh_audit_path") if "restricted_ssh_audit_path" in executor else None))


def resolve_action(action: str, profile_name: str, reason: str, requested_ttl: int | None,
                   policy: Policy, config: ExecutorConfig, requested_hours: int | None = None,
                   requested_suffixes: list[str] | None = None) -> dict[str, object]:
    if (not isinstance(reason, str) or not 1 <= len(reason) <= 500 or reason != reason.strip()
            or any(not ch.isprintable() for ch in reason)):
        raise ConfigurationError("reason must be 1-500 printable characters")
    if action == "proxy_body_capture":
        if (profile_name != "proxy_body_capture" or not policy.proxy_body_capture_enabled
                or requested_ttl is not None or requested_suffixes is not None
                or type(requested_hours) is not int
                or not 1 <= requested_hours <= 24):
            raise ConfigurationError("body capture profile or hours are not allowed")
        return {"action": action, "profile": profile_name, "operation": "enable",
                "hours": requested_hours, "ttl_seconds": requested_hours * 3600,
                "reason": "body capture diagnostics"}
    if action != "firewall_profile" or requested_hours is not None or requested_suffixes is not None:
        raise ConfigurationError("action is disabled or unknown")
    profile = policy.firewall_profiles.get(profile_name)
    if profile is None:
        raise ConfigurationError("profile is not allowed")
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
    if action["action"] == "emergency_recover":
        units = action["previously_active"]
        return ("RECOVERY: remove the Hermes direct-egress kill-switch block.\n"
                "Start only services that were active before emergency stop: "
                + (", ".join(units) if units else "none") + "\n"
                "This restores Hermes network capability. Approval is separate from emergency stop.\n"
                f"Kill-switch generation: {action['generation']}")
    if action["action"] == "proxy_body_capture":
        return (f"Enable decrypted HTTP request/response body capture for {action['hours']} hour(s).\n"
                "Profile: proxy_body_capture\n"
                "Decrypted HTTP request/response bodies will be retained on Argus for 24 hours.\n"
                "The root-owned capture helper and its independent systemd timer enforce expiry.")
    if action["action"] == "body_capture_exclusions":
        return (f"{action['operation'].capitalize()} exact body-capture exclusion: {action['hostname']}\n"
                "Resulting exact hostnames:\n" + ("\n".join(action["hosts"]) or "(none)") + "\n"
                "Only decrypted request/response bodies are suppressed for exact SNI, then Host matches. "
                "Proxy routing, DNS and connection metadata, audit logs, and firewall controls remain in force.")
    interface = f" on {action['interface']}" if action["interface"] else ""
    return (f"UFW allow {action['direction']}{interface}: {action['protocol']} "
            f"from {action['source']} to {action['destination']} port {action['port']}\n"
            f"Profile: {action['profile']}\nReason: {action['reason']}\n"
            f"Active TTL: {action['ttl_seconds']} seconds")
