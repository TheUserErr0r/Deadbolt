"""Exact UID-scoped temporary egress rules, ordered ahead of UFW denies."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import re
import shlex
import subprocess
import time
import uuid
from typing import Callable


class OutboundFirewallError(RuntimeError):
    pass


Runner = Callable[[list[str], str | None], subprocess.CompletedProcess[str]]


def _run(argv: list[str], input_text: str | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=10, check=False, shell=False)


class ExactEgress:
    """The nft guard denies every non-loopback proxy packet without a live exact grant.

    A matching owner/time UFW allow at the head of its controlled chain is also
    required, because an early nft accept cannot override UFW's later LAN deny.
    """

    TABLE = "deadbolt_ssh_proxy"
    CHAIN = "output"

    def __init__(self, hermes_uid: int, proxy_uid: int, runner: Runner = _run):
        if any(type(uid) is not int or uid <= 0 for uid in (hermes_uid, proxy_uid)) or hermes_uid == proxy_uid:
            raise OutboundFirewallError("invalid outbound account identities")
        self.hermes_uid = hermes_uid
        self.proxy_uid = proxy_uid
        self.runner = runner

    def _call(self, argv: list[str], data: str | None = None, *, missing_ok: bool = False) -> str | None:
        try:
            result = self.runner(argv, data)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OutboundFirewallError("outbound firewall command unavailable") from exc
        if result.returncode:
            if missing_ok:
                return None
            raise OutboundFirewallError("outbound firewall command failed")
        if not isinstance(result.stdout, str) or len(result.stdout) > 65536:
            raise OutboundFirewallError("invalid outbound firewall response")
        return result.stdout

    def _nft(self, *args: str, data: str | None = None, missing_ok: bool = False) -> str | None:
        return self._call(["/usr/sbin/nft", *args], data, missing_ok=missing_ok)

    def _iptables(self, ip: str, *args: str, missing_ok: bool = False) -> str | None:
        binary = "/usr/sbin/ip6tables" if ipaddress.ip_address(ip).version == 6 else "/usr/sbin/iptables"
        return self._call([binary, "-w", *args], missing_ok=missing_ok)

    def ensure_guard(self) -> None:
        text = self._nft("-a", "list", "table", "inet", self.TABLE, missing_ok=True)
        if text is None:
            uid = self.proxy_uid
            script = (f"add table inet {self.TABLE}\n"
                      f"add set inet {self.TABLE} approved4 {{ type ipv4_addr . inet_service; flags timeout; }}\n"
                      f"add set inet {self.TABLE} approved6 {{ type ipv6_addr . inet_service; flags timeout; }}\n"
                      f"add set inet {self.TABLE} raw22_4 {{ type ipv4_addr; flags timeout; }}\n"
                      f"add set inet {self.TABLE} raw22_6 {{ type ipv6_addr; flags timeout; }}\n"
                      f"add chain inet {self.TABLE} {self.CHAIN} {{ type filter hook output priority -151; policy accept; }}\n"
                      f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {self.hermes_uid} ip daddr @raw22_4 tcp dport 22 accept comment \"deadbolt-hermes-raw22-allow4\"\n"
                      f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {self.hermes_uid} ip6 daddr @raw22_6 tcp dport 22 accept comment \"deadbolt-hermes-raw22-allow6\"\n"
                      f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {self.hermes_uid} tcp dport 22 drop comment \"deadbolt-hermes-ssh-deny\"\n"
                      f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {uid} oifname \"lo\" accept comment \"deadbolt-proxy-loopback\"\n"
                      f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {uid} ip daddr . tcp dport @approved4 accept comment \"deadbolt-proxy-allow4\"\n"
                      f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {uid} ip6 daddr . tcp dport @approved6 accept comment \"deadbolt-proxy-allow6\"\n"
                      f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {uid} drop comment \"deadbolt-proxy-deny\"\n")
            self._nft("-f", "-", data=script)
            text = self._nft("-a", "list", "table", "inet", self.TABLE)
        assert text is not None
        expected = [f'meta skuid {self.hermes_uid} ip daddr @raw22_4 tcp dport 22 accept comment "deadbolt-hermes-raw22-allow4"',
                    f'meta skuid {self.hermes_uid} ip6 daddr @raw22_6 tcp dport 22 accept comment "deadbolt-hermes-raw22-allow6"',
                    f'meta skuid {self.hermes_uid} tcp dport 22 drop comment "deadbolt-hermes-ssh-deny"',
                    f'meta skuid {self.proxy_uid} oifname "lo" accept comment "deadbolt-proxy-loopback"',
                    f'meta skuid {self.proxy_uid} ip daddr . tcp dport @approved4 accept comment "deadbolt-proxy-allow4"',
                    f'meta skuid {self.proxy_uid} ip6 daddr . tcp dport @approved6 accept comment "deadbolt-proxy-allow6"',
                    f'meta skuid {self.proxy_uid} drop comment "deadbolt-proxy-deny"']
        if (not re.search(r"type filter hook output priority (?:-151|mangle - 1); policy accept;", text)
                or "set raw22_4" not in text or "set raw22_6" not in text
                or any(text.count(line) != 1 for line in expected)
                or [text.index(line) for line in expected] != sorted(text.index(line) for line in expected)):
            raise OutboundFirewallError("SSH proxy nft guard is missing or changed")

    @staticmethod
    def _validated(ip: str, port: int, transport: str, request_id: str, expiry: int) -> str:
        try:
            addr = ipaddress.ip_address(ip)
            if str(addr) != ip or addr.is_loopback or addr.is_link_local:
                raise ValueError
            if str(uuid.UUID(request_id)) != request_id:
                raise ValueError
        except ValueError as exc:
            raise OutboundFirewallError("invalid exact grant identity") from exc
        if type(port) is not int or not 1 <= port <= 65535 or transport not in ("tcp", "udp"):
            raise OutboundFirewallError("invalid exact grant endpoint")
        if type(expiry) is not int or expiry <= 0:
            raise OutboundFirewallError("invalid exact grant expiry")
        return f"deadbolt:{request_id}:{expiry}"

    def _rule(self, kind: str, ip: str, port: int, transport: str, expiry: int, tag: str) -> list[str]:
        uid = self.proxy_uid if kind == "ssh" else self.hermes_uid
        deadline = datetime.fromtimestamp(expiry, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        return ["-d", ip, "-p", transport, "--dport", str(port), "-m", "owner",
                "--uid-owner", str(uid), "-m", "time", "--datestop", deadline,
                "--utc", "-m", "comment", "--comment", tag, "-j", "ACCEPT"]

    @staticmethod
    def _chain(kind: str, port: int, transport: str) -> str:
        # Hermes's pre-output TCP/22 deny precedes ufw-user-output.
        return "ufw-before-output" if kind == "raw" and transport == "tcp" and port == 22 else "ufw-user-output"

    def _before_deny(self, ip: str, chain: str, tag: str, port: int,
                     transport: str, uid: int) -> bool:
        output = self._iptables(ip, "-S", chain)
        assert output is not None
        rules = []
        for line in output.splitlines():
            try:
                parts = shlex.split(line)
            except ValueError as exc:
                raise OutboundFirewallError("cannot parse UFW output order") from exc
            if parts[:2] == ["-A", chain]:
                rules.append(parts)
        positions = [index for index, parts in enumerate(rules)
                     if "--comment" in parts and parts[parts.index("--comment") + 1] == tag]
        if len(positions) != 1:
            return False
        address = ipaddress.ip_address(ip)
        for parts in rules[:positions[0]]:
            if "-j" not in parts or parts[parts.index("-j") + 1] not in ("DROP", "REJECT"):
                continue
            if "-d" in parts:
                try:
                    if address not in ipaddress.ip_network(parts[parts.index("-d") + 1], strict=False):
                        continue
                except ValueError as exc:
                    raise OutboundFirewallError("cannot parse UFW deny destination") from exc
            if "-p" in parts and parts[parts.index("-p") + 1] != transport:
                continue
            if "--dport" in parts and parts[parts.index("--dport") + 1] != str(port):
                continue
            if "--uid-owner" in parts and parts[parts.index("--uid-owner") + 1] != str(uid):
                continue
            return False
        return True

    def _element(self, ip: str, port: int, tag: str) -> bool:
        name = "approved4" if ipaddress.ip_address(ip).version == 4 else "approved6"
        text = self._nft("get", "element", "inet", self.TABLE, name,
                         "{", ip, ".", str(port), "}", missing_ok=True)
        if text is None:
            return False
        if f'comment "{tag}"' not in text:
            raise OutboundFirewallError("proxy nft grant belongs to another request")
        return True

    def _raw22_element(self, ip: str, tag: str) -> bool:
        name = "raw22_4" if ipaddress.ip_address(ip).version == 4 else "raw22_6"
        text = self._nft("get", "element", "inet", self.TABLE, name,
                         "{", ip, "}", missing_ok=True)
        if text is None:
            return False
        if f'comment "{tag}"' not in text:
            raise OutboundFirewallError("raw SSH nft grant belongs to another request")
        return True

    def ensure_grant(self, kind: str, ip: str, port: int, transport: str,
                     request_id: str, expiry: int, now: float) -> dict[str, object]:
        if kind not in ("ssh", "raw") or (kind == "ssh" and transport != "tcp"):
            raise OutboundFirewallError("invalid outbound grant kind")
        tag = self._validated(ip, port, transport, request_id, expiry)
        if now >= expiry:
            raise OutboundFirewallError("outbound grant has expired")
        self.ensure_guard()
        chain = self._chain(kind, port, transport)
        rule = self._rule(kind, ip, port, transport, expiry, tag)
        if kind == "ssh" and not self._element(ip, port, tag):
            name = "approved4" if ipaddress.ip_address(ip).version == 4 else "approved6"
            remaining = max(1, int(expiry - now))
            self._nft("add", "element", "inet", self.TABLE, name, "{", ip, ".", str(port),
                      "timeout", f"{remaining}s", "comment", f'"{tag}"', "}")
        if kind == "raw" and transport == "tcp" and port == 22 and not self._raw22_element(ip, tag):
            name = "raw22_4" if ipaddress.ip_address(ip).version == 4 else "raw22_6"
            remaining = max(1, int(expiry - now))
            self._nft("add", "element", "inet", self.TABLE, name, "{", ip,
                      "timeout", f"{remaining}s", "comment", f'"{tag}"', "}")
        if self._iptables(ip, "-C", chain, *rule, missing_ok=True) is None:
            self._iptables(ip, "-I", chain, "1", *rule)
        elif not self._before_deny(ip, chain, tag, port, transport,
                                   self.proxy_uid if kind == "ssh" else self.hermes_uid):
            self._iptables(ip, "-D", chain, *rule)
            self._iptables(ip, "-I", chain, "1", *rule)
        self.assert_grant(kind, ip, port, transport, request_id, expiry)
        return {"kind": kind, "ip": ip, "port": port, "transport": transport,
                "uid": self.proxy_uid if kind == "ssh" else self.hermes_uid,
                "chain": chain, "tag": tag, "expiry": expiry}

    def assert_grant(self, kind: str, ip: str, port: int, transport: str,
                     request_id: str, expiry: int) -> None:
        tag = self._validated(ip, port, transport, request_id, expiry)
        chain = self._chain(kind, port, transport)
        rule = self._rule(kind, ip, port, transport, expiry, tag)
        self.ensure_guard()
        if (self._iptables(ip, "-C", chain, *rule, missing_ok=True) is None
                or not self._before_deny(ip, chain, tag, port, transport,
                                         self.proxy_uid if kind == "ssh" else self.hermes_uid)
                or kind == "ssh" and not self._element(ip, port, tag)
                or kind == "raw" and transport == "tcp" and port == 22
                   and not self._raw22_element(ip, tag)):
            raise OutboundFirewallError("exact UID grant is absent or behind a UFW deny")

    def revoke(self, kind: str, ip: str, port: int, transport: str,
               request_id: str, expiry: int) -> None:
        tag = self._validated(ip, port, transport, request_id, expiry)
        self.ensure_guard()
        failed = False
        if kind == "ssh":
            name = "approved4" if ipaddress.ip_address(ip).version == 4 else "approved6"
            try:
                if self._element(ip, port, tag):
                    self._nft("delete", "element", "inet", self.TABLE, name,
                              "{", ip, ".", str(port), "}")
            except OutboundFirewallError:
                failed = True
        if kind == "raw" and transport == "tcp" and port == 22:
            name = "raw22_4" if ipaddress.ip_address(ip).version == 4 else "raw22_6"
            try:
                if self._raw22_element(ip, tag):
                    self._nft("delete", "element", "inet", self.TABLE, name, "{", ip, "}")
            except OutboundFirewallError:
                failed = True
        chain = self._chain(kind, port, transport)
        rule = self._rule(kind, ip, port, transport, expiry, tag)
        try:
            if self._iptables(ip, "-C", chain, *rule, missing_ok=True) is not None:
                self._iptables(ip, "-D", chain, *rule)
        except OutboundFirewallError:
            failed = True
        if (failed or self._iptables(ip, "-C", chain, *rule, missing_ok=True) is not None
                or kind == "ssh" and self._element(ip, port, tag)
                or kind == "raw" and transport == "tcp" and port == 22
                   and self._raw22_element(ip, tag)):
            raise OutboundFirewallError("exact outbound grant remains after revoke")
