"""Two-layer, UID-scoped TCP/22 grants for the dedicated SSH broker."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
import re
import shlex
import subprocess
import uuid
from typing import Callable


class BrokerFirewallError(RuntimeError):
    pass


Command = Callable[[list[str], str | None], subprocess.CompletedProcess[str]]


def _command(argv: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=10, check=False, shell=False)


class BrokerFirewall:
    TABLE = "deadbolt_ssh"
    CHAIN = "output"
    UFW_CHAIN = "ufw-user-output"

    def __init__(self, broker_uid: int, runner: Command = _command):
        if type(broker_uid) is not int or broker_uid <= 0:
            raise BrokerFirewallError("invalid SSH broker UID")
        self.uid = broker_uid
        self.runner = runner

    def _run(self, argv: list[str], input_text: str | None = None,
             *, allow_missing: bool = False) -> str | None:
        try:
            result = self.runner(argv, input_text)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BrokerFirewallError("broker firewall command unavailable") from exc
        if result.returncode:
            if allow_missing:
                return None
            raise BrokerFirewallError("broker firewall command failed")
        if not isinstance(result.stdout, str) or len(result.stdout) > 65536:
            raise BrokerFirewallError("invalid broker firewall response")
        return result.stdout

    def _nft(self, *args: str, input_text: str | None = None,
             allow_missing: bool = False) -> str | None:
        return self._run(["/usr/sbin/nft", *args], input_text, allow_missing=allow_missing)

    def _iptables(self, ip: str, *args: str, allow_missing: bool = False) -> str | None:
        binary = "/usr/sbin/ip6tables" if ipaddress.ip_address(ip).version == 6 else "/usr/sbin/iptables"
        return self._run([binary, "-w", *args], allow_missing=allow_missing)

    def _script(self) -> str:
        # Contains only a numeric UID from the root-owned local account DB.
        uid = self.uid
        return (f"add table inet {self.TABLE}\n"
                f"add set inet {self.TABLE} approved4 {{ type ipv4_addr; flags timeout; }}\n"
                f"add set inet {self.TABLE} approved6 {{ type ipv6_addr; flags timeout; }}\n"
                f"add chain inet {self.TABLE} {self.CHAIN} {{ type filter hook output priority -1; policy accept; }}\n"
                f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {uid} ip daddr @approved4 tcp dport 22 accept comment \"deadbolt-ssh-allow4\"\n"
                f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {uid} ip6 daddr @approved6 tcp dport 22 accept comment \"deadbolt-ssh-allow6\"\n"
                f"add rule inet {self.TABLE} {self.CHAIN} meta skuid {uid} tcp dport 22 drop comment \"deadbolt-ssh-deny\"\n")

    def ensure_guard(self) -> None:
        current = self._nft("-a", "list", "table", "inet", self.TABLE, allow_missing=True)
        if current is None:
            self._nft("-f", "-", input_text=self._script())
            current = self._nft("-a", "list", "table", "inet", self.TABLE)
        assert current is not None
        # Reject a missing or externally changed guard instead of silently
        # trusting an early-chain accept that UFW might still drop.
        if (not re.search(r"type filter hook output priority (?:filter - 1|-1); policy accept;", current)
                or f"meta skuid {self.uid} ip daddr @approved4 tcp dport 22 accept comment \"deadbolt-ssh-allow4\"" not in current
                or f"meta skuid {self.uid} ip6 daddr @approved6 tcp dport 22 accept comment \"deadbolt-ssh-allow6\"" not in current
                or f"meta skuid {self.uid} tcp dport 22 drop comment \"deadbolt-ssh-deny\"" not in current
                or current.count('comment "deadbolt-ssh-allow4"') != 1
                or current.count('comment "deadbolt-ssh-allow6"') != 1
                or current.count('comment "deadbolt-ssh-deny"') != 1
                or current.index('comment "deadbolt-ssh-allow4"') > current.index('comment "deadbolt-ssh-deny"')
                or current.index('comment "deadbolt-ssh-allow6"') > current.index('comment "deadbolt-ssh-deny"')):
            raise BrokerFirewallError("broker nftables guard is missing or changed")

    @staticmethod
    def _identity(request_id: str, expiry: int) -> str:
        try:
            if str(uuid.UUID(request_id)) != request_id or type(expiry) is not int or expiry <= 0:
                raise ValueError
        except ValueError as exc:
            raise BrokerFirewallError("invalid broker grant identity") from exc
        return f"deadbolt:{request_id}:{expiry}"

    @staticmethod
    def _address(value: str) -> tuple[str, str]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise BrokerFirewallError("invalid pinned broker IP") from exc
        if str(address) != value or address.is_loopback or address.is_link_local:
            raise BrokerFirewallError("noncanonical pinned broker IP")
        return value, "approved4" if address.version == 4 else "approved6"

    def _ufw_args(self, ip: str, tag: str, expiry: int) -> list[str]:
        deadline = datetime.fromtimestamp(expiry, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        return ["-d", ip, "-p", "tcp", "--dport", "22", "-m", "owner",
                "--uid-owner", str(self.uid), "-m", "time", "--datestop", deadline,
                "--utc", "-m", "comment", "--comment", tag,
                "-j", "ACCEPT"]

    def _ufw_present(self, ip: str, tag: str, expiry: int) -> bool:
        return self._iptables(ip, "-C", self.UFW_CHAIN, *self._ufw_args(ip, tag, expiry),
                              allow_missing=True) is not None

    def _element_text(self, ip: str, set_name: str) -> str | None:
        return self._nft("get", "element", "inet", self.TABLE, set_name,
                         "{", ip, "}", allow_missing=True)

    def _element_present(self, ip: str, set_name: str, tag: str) -> bool:
        found = self._element_text(ip, set_name)
        if found is None:
            return False
        if f'comment "{tag}"' not in found:
            raise BrokerFirewallError("broker nft element belongs to another grant")
        return True

    def _check_static_bypass(self) -> None:
        for ip in ("0.0.0.0", "::"):
            binary = "/usr/sbin/ip6tables" if ip == "::" else "/usr/sbin/iptables"
            for chain in ("ufw-before-output", self.UFW_CHAIN):
                text = self._run([binary, "-w", "-S", chain])
                assert text is not None
                for line in text.splitlines():
                    try:
                        tokens = shlex.split(line)
                    except ValueError as exc:
                        raise BrokerFirewallError("cannot parse UFW output chain") from exc
                    if "-A" not in tokens:
                        continue
                    if "-j" not in tokens or tokens.index("-j") + 1 >= len(tokens):
                        raise BrokerFirewallError("cannot parse UFW output verdict")
                    if ("--dport" in tokens and "22" in tokens
                            and tokens[tokens.index("-j") + 1] == "ACCEPT"):
                        comment = (tokens[tokens.index("--comment") + 1]
                                   if "--comment" in tokens and tokens.index("--comment") + 1 < len(tokens)
                                   else "")
                        if (chain != self.UFW_CHAIN or not comment.startswith("deadbolt:")
                                or "--uid-owner" not in tokens
                                or tokens[tokens.index("--uid-owner") + 1] != str(self.uid)):
                            raise BrokerFirewallError("static SSH allow must be removed before broker migration")

    def ensure_grant(self, ip: str, request_id: str, expiry: int, now: float) -> dict[str, object]:
        ip, set_name = self._address(ip)
        tag = self._identity(request_id, expiry)
        if now >= expiry:
            raise BrokerFirewallError("broker grant is already expired")
        self.ensure_guard()
        self._check_static_bypass()
        if not self._element_present(ip, set_name, tag):
            remaining = max(1, int(expiry - now))
            self._nft("add", "element", "inet", self.TABLE, set_name,
                      "{", ip, "timeout", f"{remaining}s", "comment", f'"{tag}"', "}")
        if not self._ufw_present(ip, tag, expiry):
            self._iptables(ip, "-I", self.UFW_CHAIN, "1", *self._ufw_args(ip, tag, expiry))
        self.assert_grant(ip, request_id, expiry)
        return {"pinned_ip": ip, "uid": self.uid, "nft_set": set_name,
                "ufw_chain": self.UFW_CHAIN, "tag": tag, "expiry": expiry}

    def assert_grant(self, ip: str, request_id: str, expiry: int) -> None:
        ip, set_name = self._address(ip)
        tag = self._identity(request_id, expiry)
        self.ensure_guard()
        if not self._element_present(ip, set_name, tag) or not self._ufw_present(ip, tag, expiry):
            raise BrokerFirewallError("exact broker grant is absent")

    def revoke(self, ip: str, request_id: str, expiry: int) -> None:
        ip, set_name = self._address(ip)
        tag = self._identity(request_id, expiry)
        if self._ufw_present(ip, tag, expiry):
            self._iptables(ip, "-D", self.UFW_CHAIN, *self._ufw_args(ip, tag, expiry))
        if self._element_present(ip, set_name, tag):
            self._nft("delete", "element", "inet", self.TABLE, set_name, "{", ip, "}")
        if self._ufw_present(ip, tag, expiry) or self._element_present(ip, set_name, tag):
            raise BrokerFirewallError("broker grant remains after revoke")
