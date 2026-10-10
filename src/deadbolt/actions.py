"""Explicit privileged actions. Only UFW profiles are enabled in v0.5."""

from __future__ import annotations

import shlex
import subprocess
from typing import Any, Callable, Protocol

from deadbolt.config import describe_action


class ActionError(RuntimeError):
    pass


class Action(Protocol):
    def validate(self, request: dict[str, Any]) -> None: ...
    def describe(self, request: dict[str, Any]) -> str: ...
    def prepare(self, request: dict[str, Any], grant_id: str) -> dict[str, Any]: ...
    def apply(self, request: dict[str, Any], rollback: dict[str, Any]) -> None: ...
    def rollback(self, request: dict[str, Any], rollback: dict[str, Any]) -> None: ...


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _subprocess_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=15, check=False)


class UfwAction:
    def __init__(self, runner: Runner = _subprocess_runner, executable: str = "/usr/sbin/ufw"):
        self.runner = runner
        self.executable = executable

    def validate(self, request: dict[str, Any]) -> None:
        expected = {"action", "profile", "direction", "protocol", "source", "destination",
                    "port", "interface", "reason", "ttl_seconds"}
        if set(request) != expected or request["action"] != "firewall_profile":
            raise ActionError("invalid resolved firewall action")
        if request["direction"] not in ("in", "out") or request["protocol"] not in ("tcp", "udp"):
            raise ActionError("invalid resolved firewall parameters")
        # Network, port, and interface values come only from root-owned parsed policy.

    def describe(self, request: dict[str, Any]) -> str:
        self.validate(request)
        return describe_action(request)

    def _rule(self, request: dict[str, Any]) -> list[str]:
        rule = ["allow", str(request["direction"])]
        if request["interface"]:
            rule += ["on", str(request["interface"])]
        rule += ["proto", str(request["protocol"]), "from", str(request["source"]),
                 "to", str(request["destination"]), "port", str(request["port"])]
        return rule

    def _run(self, args: list[str]) -> str:
        result = self.runner([self.executable, *args])
        if result.returncode != 0:
            raise ActionError(f"ufw command failed with exit code {result.returncode}")
        return result.stdout

    def _added(self) -> list[tuple[list[str], str | None]]:
        output = self._run(["show", "added"])
        rules: list[tuple[list[str], str | None]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("ufw "):
                continue
            try:
                tokens = shlex.split(line)
            except ValueError as exc:
                raise ActionError("cannot parse UFW rules") from exc
            if len(tokens) < 2 or tokens[0] != "ufw":
                raise ActionError("cannot parse UFW rules")
            tokens = tokens[1:]
            comment: str | None = None
            if "comment" in tokens:
                index = tokens.index("comment")
                if index != len(tokens) - 2:
                    raise ActionError("ambiguous UFW rule comment")
                comment = tokens[-1]
                tokens = tokens[:index]
            rules.append((tokens, comment))
        return rules

    def _ensure_active(self) -> None:
        if self._run(["status"]).splitlines()[:1] != ["Status: active"]:
            raise ActionError("UFW is not active")

    def prepare(self, request: dict[str, Any], grant_id: str) -> dict[str, Any]:
        self.validate(request)
        self._ensure_active()
        expected = self._rule(request)
        tag = f"deadbolt:{grant_id}"
        added = self._added()
        matches = [(rule, comment) for rule, comment in added if rule == expected]
        if matches:
            if len(matches) != 1 or (matches[0][1] and matches[0][1].startswith("deadbolt:")):
                raise ActionError("matching firewall rule is ambiguous or already managed")
            return {"mutation": "none", "rule": expected, "tag": tag}
        for rule, _comment in added:
            # UFW's text output is not a machine API. If a possibly equivalent
            # rule uses another syntax, refuse rather than risk changing it.
            if rule[:1] == ["allow"] and str(request["port"]) in rule and rule != expected:
                if str(request["protocol"]) in rule and str(request["direction"]) in rule:
                    raise ActionError("ambiguous UFW rule on the requested port")
        return {"mutation": "tagged", "rule": expected, "tag": tag}

    def apply(self, request: dict[str, Any], rollback: dict[str, Any]) -> None:
        self.validate(request)
        self._ensure_active()
        if rollback["rule"] != self._rule(request):
            raise ActionError("rollback intent does not match resolved action")
        if rollback["mutation"] == "none":
            return
        if rollback["mutation"] != "tagged":
            raise ActionError("invalid rollback intent")
        # Re-check immediately before mutation. Serialized Deadbolt operations
        # cannot race each other; external administrator changes fail closed.
        for rule, comment in self._added():
            if rule == rollback["rule"]:
                raise ActionError("firewall rule changed before apply")
        self._run([*rollback["rule"], "comment", rollback["tag"]])
        if (rollback["rule"], rollback["tag"]) not in self._added():
            raise ActionError("tagged firewall rule could not be verified")

    def rollback(self, request: dict[str, Any], rollback: dict[str, Any]) -> None:
        self.validate(request)
        if rollback["rule"] != self._rule(request):
            raise ActionError("rollback intent does not match resolved action")
        if rollback["mutation"] == "none":
            return
        if rollback["mutation"] != "tagged":
            raise ActionError("invalid rollback intent")
        matches = [(rule, comment) for rule, comment in self._added() if rule == rollback["rule"]]
        tagged = [(rule, comment) for rule, comment in matches if comment == rollback["tag"]]
        if not tagged:
            if matches:
                raise ActionError("tag disappeared but equivalent access remains; manual reconciliation required")
            return  # Already removed; idempotent.
        if len(tagged) != 1 or len(matches) != 1:
            raise ActionError("ambiguous firewall rule; manual reconciliation required")
        self._run(["delete", *rollback["rule"], "comment", rollback["tag"]])
        if (rollback["rule"], rollback["tag"]) in self._added():
            raise ActionError("tagged firewall rule remains after rollback")


class DisabledAction:
    """Fail-closed placeholder for future Teleport and service actions."""

    def validate(self, request: dict[str, Any]) -> None:
        raise ActionError("action is disabled in v0.5")

    def describe(self, request: dict[str, Any]) -> str:
        self.validate(request)
        raise AssertionError("unreachable")

    def prepare(self, request: dict[str, Any], grant_id: str) -> dict[str, Any]:
        self.validate(request)
        raise AssertionError("unreachable")

    def apply(self, request: dict[str, Any], rollback: dict[str, Any]) -> None:
        self.validate(request)

    def rollback(self, request: dict[str, Any], rollback: dict[str, Any]) -> None:
        self.validate(request)
