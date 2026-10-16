"""Exact, time-limited inbound UFW grants with an earlier nft expiry guard."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import re
import shlex
import subprocess
import time
import uuid
from typing import Callable

from deadbolt.ingress import IngressError, _local_ip, _network


class IngressFirewallError(RuntimeError):
    pass


Runner = Callable[[list[str], str | None], subprocess.CompletedProcess[str]]


def _run(argv: list[str], input_text: str | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=10, check=False, shell=False)


class IngressFirewall:
    TABLE = "deadbolt_ingress"
    CHAIN = "input"
    UFW_CHAIN = "ufw-before-input"

    def __init__(self, runner: Runner = _run):
        self.runner = runner

    def _call(self, argv: list[str], data: str | None = None, *, missing_ok: bool = False) -> str | None:
        try:
            result = self.runner(argv, data)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise IngressFirewallError("ingress firewall command unavailable") from exc
        if result.returncode:
            if missing_ok:
                return None
            raise IngressFirewallError("ingress firewall command failed")
        if not isinstance(result.stdout, str) or len(result.stdout) > 65536:
            raise IngressFirewallError("invalid ingress firewall response")
        return result.stdout

    def _nft(self, *args: str, data: str | None = None, missing_ok: bool = False) -> str | None:
        return self._call(["/usr/sbin/nft", *args], data, missing_ok=missing_ok)

    def _iptables(self, version: int, *args: str, missing_ok: bool = False) -> str | None:
        binary = "/usr/sbin/ip6tables" if version == 6 else "/usr/sbin/iptables"
        return self._call([binary, "-w", *args], missing_ok=missing_ok)

    def _ensure_ufw_active(self) -> None:
        status = self._call(["/usr/sbin/ufw", "status", "verbose"])
        if (not status or status.splitlines()[:1] != ["Status: active"]
                or not re.search(r"^Default: deny \(incoming\)", status, re.MULTILINE)):
            raise IngressFirewallError("UFW must be active with default incoming deny")

    @staticmethod
    def _identity(request_id: str, expiry: int) -> tuple[str, str]:
        try:
            if str(uuid.UUID(request_id)) != request_id or type(expiry) is not int or expiry <= 0:
                raise ValueError
        except ValueError as exc:
            raise IngressFirewallError("invalid ingress grant identity") from exc
        return f"src_{uuid.UUID(request_id).hex}", f"deadbolt-ingress:{request_id}:{expiry}"

    @staticmethod
    def _scope(record: dict[str, object]) -> tuple[int, str, str, str, str, str]:
        try:
            source = _network(record["source"])
            local = _local_ip(record["local_ip"])
            protocol = record["protocol"]
            lo, hi = record["port_start"], record["port_end"]
            if (source.version != ipaddress.ip_address(local).version
                    or protocol not in ("tcp", "udp")
                    or type(lo) is not int or type(hi) is not int
                    or not 1024 <= lo <= hi <= 65535 or hi - lo >= 16):
                raise ValueError
        except (KeyError, ValueError, IngressError) as exc:
            raise IngressFirewallError("invalid resolved ingress scope") from exc
        nft_source = (str(source.network_address) if source.prefixlen == source.max_prefixlen
                      else str(source))
        ports = str(lo) if lo == hi else f"{lo}-{hi}"
        iptables_ports = str(lo) if lo == hi else f"{lo}:{hi}"
        return source.version, str(source), nft_source, local, ports, iptables_ports

    def assert_local_ip(self, local_ip: str) -> None:
        _local_ip(local_ip)
        raw = self._call(["/usr/sbin/ip", "-j", "address", "show"])
        try:
            interfaces = json.loads(raw or "")
            found = any(item.get("ifname") != "lo" and
                        any(address.get("local") == local_ip
                            for address in item.get("addr_info", []))
                        for item in interfaces)
        except (ValueError, TypeError, AttributeError) as exc:
            raise IngressFirewallError("cannot verify Hermes LAN address") from exc
        if not found:
            raise IngressFirewallError("local destination is not assigned to a non-loopback interface")

    def ensure_guard(self) -> None:
        text = self._nft("-a", "list", "table", "inet", self.TABLE, missing_ok=True)
        if text is None:
            script = (f"add table inet {self.TABLE}\n"
                      f"add chain inet {self.TABLE} {self.CHAIN} "
                      "{ type filter hook input priority -151; policy accept; }\n")
            self._nft("-f", "-", data=script)
            text = self._nft("-a", "list", "table", "inet", self.TABLE)
        # nft prints the numeric priority as either -151 or "mangle - 1".
        if not text or not re.search(
                r"type filter hook input priority (?:-151|mangle - 1); policy accept;", text):
            raise IngressFirewallError("early ingress nft guard is missing or changed")

    @staticmethod
    def _nft_rule(record: dict[str, object], set_name: str, tag: str,
                  *, allow: bool) -> list[str]:
        version, _source, nft_source, local, ports, _ = IngressFirewall._scope(record)
        address = "ip6" if version == 6 else "ip"
        proto = str(record["protocol"])
        source = [address, "saddr", f"@{set_name}"] if allow else [address, "saddr", nft_source]
        return [*source, address, "daddr", local, proto, "dport", ports,
                "accept" if allow else "drop", "comment", f'"{tag}-{ "allow" if allow else "deny" }"']

    @staticmethod
    def _ufw_rule(record: dict[str, object], tag: str, expiry: int, *, allow: bool) -> list[str]:
        _version, source, _nft_source, local, _ports, iptables_ports = IngressFirewall._scope(record)
        rule = ["-s", source, "-d", local, "-p", str(record["protocol"]),
                "--dport", iptables_ports]
        if allow:
            deadline = datetime.fromtimestamp(expiry, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            rule += ["-m", "time", "--datestop", deadline, "--utc"]
        return [*rule, "-m", "comment", "--comment", f"{tag}-{'allow' if allow else 'deny'}",
                "-j", "ACCEPT" if allow else "DROP"]

    def _nft_rules(self, tag: str) -> tuple[str | None, str | None]:
        text = self._nft("-a", "list", "chain", "inet", self.TABLE, self.CHAIN)
        assert text is not None
        found = []
        for suffix in ("allow", "deny"):
            lines = [line for line in text.splitlines() if f'comment "{tag}-{suffix}"' in line]
            if len(lines) > 1:
                raise IngressFirewallError("duplicate ingress nft rule")
            found.append(lines[0] if lines else None)
        return found[0], found[1]

    def _ufw_positions(self, version: int, tag: str) -> tuple[int | None, int | None, int]:
        text = self._iptables(version, "-S", self.UFW_CHAIN)
        assert text is not None
        lines = []
        for line in text.splitlines():
            try:
                parts = shlex.split(line)
            except ValueError as exc:
                raise IngressFirewallError("cannot parse UFW ingress rules") from exc
            if parts[:2] == ["-A", self.UFW_CHAIN]:
                lines.append(parts)
        positions = []
        for suffix in ("allow", "deny"):
            hits = [index for index, parts in enumerate(lines)
                    if "--comment" in parts and
                    parts[parts.index("--comment") + 1] == f"{tag}-{suffix}"]
            if len(hits) > 1:
                raise IngressFirewallError("duplicate ingress UFW rule")
            positions.append(hits[0] if hits else None)
        first_other = next((index for index, parts in enumerate(lines)
                            if not any(part.startswith("deadbolt-ingress:")
                                       for part in parts)), len(lines))
        return positions[0], positions[1], first_other

    def _ensure_drop(self, record: dict[str, object], request_id: str, expiry: int,
                     *, ufw: bool = True) -> None:
        version, _source, _nft_source, _local, _ports, _ = self._scope(record)
        set_name, tag = self._identity(request_id, expiry)
        self.ensure_guard()
        _allow_line, deny_line = self._nft_rules(tag)
        if deny_line is None:
            self._nft("insert", "rule", "inet", self.TABLE, self.CHAIN,
                      *self._nft_rule(record, set_name, tag, allow=False))
        if ufw:
            deny_rule = self._ufw_rule(record, tag, expiry, allow=False)
            if self._iptables(version, "-C", self.UFW_CHAIN, *deny_rule, missing_ok=True) is None:
                self._iptables(version, "-I", self.UFW_CHAIN, "1", *deny_rule)

    def ensure_grant(self, record: dict[str, object], request_id: str,
                     expiry: int, now: float) -> dict[str, object]:
        version, source, nft_source, _local, _ports, _ = self._scope(record)
        if now >= expiry:
            raise IngressFirewallError("ingress grant has expired")
        self.assert_local_ip(str(record["local_ip"]))
        self._ensure_ufw_active()
        set_name, tag = self._identity(request_id, expiry)
        self._ensure_drop(record, request_id, expiry)
        if self._nft("list", "set", "inet", self.TABLE, set_name, missing_ok=True) is None:
            addr_type = "ipv6_addr" if version == 6 else "ipv4_addr"
            self._nft("add", "set", "inet", self.TABLE, set_name,
                      "{", "type", addr_type, ";", "flags", "interval,timeout", ";", "}")
        active = self._nft("get", "element", "inet", self.TABLE, set_name,
                           "{", nft_source, "}", missing_ok=True)
        if active is None:
            seconds = max(1, int(expiry - now))
            self._nft("add", "element", "inet", self.TABLE, set_name,
                      "{", nft_source, "timeout", f"{seconds}s", "comment", f'"{tag}"', "}")
        allow_line, deny_line = self._nft_rules(tag)
        if allow_line is None:
            self._nft("insert", "rule", "inet", self.TABLE, self.CHAIN,
                      *self._nft_rule(record, set_name, tag, allow=True))
        elif deny_line is None or allow_line == deny_line:
            raise IngressFirewallError("ingress nft guard order cannot be verified")
        allow_rule = self._ufw_rule(record, tag, expiry, allow=True)
        if self._iptables(version, "-C", self.UFW_CHAIN, *allow_rule, missing_ok=True) is None:
            self._iptables(version, "-I", self.UFW_CHAIN, "1", *allow_rule)
        allow_position, deny_position, first_other = self._ufw_positions(version, tag)
        if (allow_position is None or deny_position is None or
                not allow_position < deny_position < first_other):
            # A reload or interrupted insertion can change order. Remove only
            # our exact tagged pair, then put both ahead of UFW's state accept.
            if self._iptables(version, "-C", self.UFW_CHAIN, *allow_rule, missing_ok=True) is not None:
                self._iptables(version, "-D", self.UFW_CHAIN, *allow_rule)
            deny_rule = self._ufw_rule(record, tag, expiry, allow=False)
            if self._iptables(version, "-C", self.UFW_CHAIN, *deny_rule, missing_ok=True) is not None:
                self._iptables(version, "-D", self.UFW_CHAIN, *deny_rule)
            self._iptables(version, "-I", self.UFW_CHAIN, "1", *deny_rule)
            self._iptables(version, "-I", self.UFW_CHAIN, "1", *allow_rule)
        self.assert_grant(record, request_id, expiry)
        return {"source": source, "local_ip": record["local_ip"],
                "protocol": record["protocol"], "port_start": record["port_start"],
                "port_end": record["port_end"], "expiry": expiry, "tag": tag}

    def assert_grant(self, record: dict[str, object], request_id: str, expiry: int) -> None:
        version, source, nft_source, _local, _ports, _ = self._scope(record)
        self.assert_local_ip(str(record["local_ip"]))
        self._ensure_ufw_active()
        set_name, tag = self._identity(request_id, expiry)
        self.ensure_guard()
        active = self._nft("get", "element", "inet", self.TABLE, set_name,
                           "{", nft_source, "}", missing_ok=True)
        details = self._nft("list", "set", "inet", self.TABLE, set_name,
                            missing_ok=True)
        allow_line, deny_line = self._nft_rules(tag)
        chain = self._nft("-a", "list", "chain", "inet", self.TABLE, self.CHAIN) or ""
        allow_rule = self._ufw_rule(record, tag, expiry, allow=True)
        deny_rule = self._ufw_rule(record, tag, expiry, allow=False)
        ufw_allow, ufw_deny, first_other = self._ufw_positions(version, tag)
        # nft get element omits timeout/comment metadata for interval CIDRs;
        # list set retains it. Require both exact membership and the timed
        # tagged element in the set listing.
        if (active is None or details is None
                or f"{nft_source} timeout" not in details
                or f'comment "{tag}"' not in details
                or allow_line is None or deny_line is None
                or chain.index(allow_line) > chain.index(deny_line)
                or self._iptables(version, "-C", self.UFW_CHAIN, *allow_rule, missing_ok=True) is None
                or self._iptables(version, "-C", self.UFW_CHAIN, *deny_rule, missing_ok=True) is None
                or ufw_allow is None or ufw_deny is None
                or not ufw_allow < ufw_deny < first_other):
            raise IngressFirewallError("exact timed ingress grant or expiry guard is absent")

    def revoke(self, record: dict[str, object], request_id: str, expiry: int) -> None:
        version, source, nft_source, _local, _ports, _ = self._scope(record)
        set_name, tag = self._identity(request_id, expiry)
        self._ensure_drop(record, request_id, expiry, ufw=False)
        if self._nft("get", "element", "inet", self.TABLE, set_name,
                     "{", nft_source, "}", missing_ok=True) is not None:
            self._nft("delete", "element", "inet", self.TABLE, set_name, "{", nft_source, "}")
        # Clear the early accept before touching UFW. Even if UFW has been
        # reloaded or is unavailable, this grant's nft deny now catches any
        # established connection that would otherwise bypass UFW's rules.
        self._ensure_drop(record, request_id, expiry)
        allow_rule = self._ufw_rule(record, tag, expiry, allow=True)
        if self._iptables(version, "-C", self.UFW_CHAIN, *allow_rule, missing_ok=True) is not None:
            self._iptables(version, "-D", self.UFW_CHAIN, *allow_rule)
        if (self._nft("get", "element", "inet", self.TABLE, set_name,
                      "{", nft_source, "}", missing_ok=True) is not None
                or self._iptables(version, "-C", self.UFW_CHAIN, *allow_rule,
                                  missing_ok=True) is not None):
            raise IngressFirewallError("ingress accept remains after revoke")
