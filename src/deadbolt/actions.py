"""Explicit privileged actions with fixed executable and argument contracts."""

from __future__ import annotations

import shlex
import json
import hashlib
import os
from pathlib import Path
import grp
import re
import stat
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from deadbolt.config import describe_action


class ActionError(RuntimeError):
    pass


class CaptureError(ActionError):
    def __init__(self, message: str, outcome: str | None = None):
        super().__init__(message)
        self.outcome = outcome


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
        # Match the form emitted by `ufw show added`. UFW rewrites input rules
        # into this form; comparing against the input argv would miss a rule
        # after it had already been applied.
        rule = ["allow"]
        if request["interface"]:
            rule += [str(request["direction"]), "on", str(request["interface"])]
        elif request["direction"] == "out":
            rule += ["out"]
        source = str(request["source"])
        destination = str(request["destination"])
        if source not in ("any", "0.0.0.0/0", "::/0"):
            rule += ["from", source]
        if destination in ("0.0.0.0/0", "::/0"):
            destination = "any"
        rule += ["to", destination, "port", str(request["port"]),
                 "proto", str(request["protocol"])]
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


class CaptureAction:
    """Adapter for the separately deployed, root-owned body-capture helper."""

    executable = "/usr/local/sbin/hermes-body-capture"
    outcomes = frozenset({"enabled", "disabled", "status", "expired", "invalid_ttl", "internal_error"})
    timestamp = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

    def __init__(self, runner: Runner | None = None):
        self.runner = runner or self._runner

    @staticmethod
    def _runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        path = Path(CaptureAction.executable)
        parent = path.parent.stat()
        info = path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022
                or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise ActionError("unsafe capture helper executable")
        return subprocess.run(argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=15, check=False)

    def validate(self, request: dict[str, Any]) -> None:
        if (set(request) != {"action", "profile", "operation", "hours", "ttl_seconds", "reason"}
                or request["action"] != "proxy_body_capture"
                or request["profile"] != "proxy_body_capture"
                or request["operation"] != "enable"
                or type(request["hours"]) is not int or not 1 <= request["hours"] <= 24
                or request["ttl_seconds"] != request["hours"] * 3600):
            raise ActionError("invalid resolved body capture action")

    def describe(self, request: dict[str, Any]) -> str:
        self.validate(request)
        return describe_action(request)

    def _run(self, operation: str, hours: int | None = None) -> dict[str, Any]:
        if operation not in ("enable", "disable", "status"):
            raise ActionError("invalid capture operation")
        if operation == "enable" and (type(hours) is not int or not 1 <= hours <= 24):
            raise ActionError("invalid capture hours")
        if operation != "enable" and hours is not None:
            raise ActionError("invalid capture arguments")
        argv = [self.executable, "--json", operation]
        if hours is not None:
            argv.append(str(hours))
        try:
            result = self.runner(argv)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ActionError("capture helper unavailable") from exc
        # The helper's stderr and unparsed stdout may contain evidence. Never
        # include them in exceptions, logs, Discord messages, or audit events.
        if not isinstance(result.stdout, str) or len(result.stdout) > 4096 or result.stdout.count("\n") > 1:
            raise ActionError("invalid capture helper response")
        try:
            record = json.loads(result.stdout)
        except (TypeError, ValueError) as exc:
            raise ActionError("invalid capture helper response") from exc
        if (not isinstance(record, dict) or set(record) != {"enabled", "expires_at", "outcome"}
                or type(record["enabled"]) is not bool or not isinstance(record["outcome"], str)
                or record["outcome"] not in self.outcomes):
            raise ActionError("invalid capture helper response")
        expiry = record["expires_at"]
        if expiry is not None:
            if not isinstance(expiry, str) or not self.timestamp.fullmatch(expiry):
                raise ActionError("invalid capture helper response")
            try:
                datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError as exc:
                raise ActionError("invalid capture helper response") from exc
        if record["enabled"] != (expiry is not None):
            raise ActionError("invalid capture helper response")
        if record["outcome"] == "expired" and record["enabled"]:
            raise ActionError("invalid capture helper response")
        if result.returncode != 0 or record["outcome"] in ("invalid_ttl", "internal_error"):
            raise CaptureError(f"capture helper outcome: {record['outcome']}", record["outcome"])
        if operation == "enable" and (record["outcome"] != "enabled" or not record["enabled"]):
            raise ActionError("capture helper did not enable")
        if operation == "disable" and (record["outcome"] not in ("disabled", "expired") or record["enabled"]):
            raise ActionError("capture helper did not disable")
        if operation == "status" and record["outcome"] not in ("status", "expired"):
            raise ActionError("invalid capture helper response")
        return record

    def enable(self, request: dict[str, Any]) -> dict[str, Any]:
        self.validate(request)
        return self._run("enable", request["hours"])

    def status(self) -> dict[str, Any]:
        return self._run("status")

    def disable(self) -> dict[str, Any]:
        return self._run("disable")


class ExclusionsAction:
    """Atomically replace the root-owned body-only DNS suffix file."""

    path = Path("/etc/hermes-inspection-proxy/body-capture-exclusions.conf")
    header = "# Deadbolt body-capture exclusions; proxy metadata remains logged.\n"

    def __init__(self, path: Path | None = None, group_id: int | None = None,
                 owner_id: int = 0):
        self.path = path or self.path
        self.group_id = group_id
        self.owner_id = owner_id

    def validate(self, request: dict[str, Any]) -> None:
        from deadbolt.config import normalize_suffixes
        if (set(request) != {"action", "profile", "operation", "suffixes", "ttl_seconds", "reason"}
                or request["action"] != "body_capture_exclusions"
                or request["profile"] != "body_capture_exclusions" or request["operation"] != "replace"
                or request["ttl_seconds"] != 0 or not isinstance(request["suffixes"], list)
                or tuple(request["suffixes"]) != normalize_suffixes(request["suffixes"])):
            raise ActionError("invalid resolved exclusions action")

    def describe(self, request: dict[str, Any]) -> str:
        self.validate(request)
        return describe_action(request)

    def _read(self) -> str:
        parent = self.path.parent.stat()
        own = self.path.lstat()
        expected_gid = self.group_id if self.group_id is not None else grp.getgrnam("tlsproxy").gr_gid
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != self.owner_id or parent.st_mode & 0o022
                or not stat.S_ISREG(own.st_mode) or own.st_uid != self.owner_id or own.st_gid != expected_gid
                or stat.S_IMODE(own.st_mode) != 0o640):
            raise ActionError("unsafe exclusions file")
        data = self.path.read_bytes()
        if len(data) > 8192:
            raise ActionError("exclusions file is too large")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ActionError("invalid exclusions file encoding") from exc

    def prepare(self, request: dict[str, Any]) -> dict[str, Any]:
        self.validate(request)
        before = self._read()
        after = self.header + "".join(f"{suffix}\n" for suffix in request["suffixes"])
        return {"before_sha256": hashlib.sha256(before.encode()).hexdigest(), "after": after}

    def apply(self, request: dict[str, Any], intent: dict[str, Any]) -> None:
        self.validate(request)
        if intent["after"] != self.header + "".join(f"{suffix}\n" for suffix in request["suffixes"]):
            raise ActionError("exclusions intent does not match approval")
        current = self._read()
        if current == intent["after"]:
            return
        if hashlib.sha256(current.encode()).hexdigest() != intent["before_sha256"]:
            raise ActionError("exclusions changed before apply")
        gid = self.group_id if self.group_id is not None else grp.getgrnam("tlsproxy").gr_gid
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fchown(fd, self.owner_id, gid)
                os.fchmod(fd, 0o640)
                data = intent["after"].encode("utf-8")
                while data:
                    written = os.write(fd, data)
                    if written == 0:
                        raise ActionError("exclusions write made no progress")
                    data = data[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        if self._read() != intent["after"]:
            raise ActionError("exclusions replacement could not be verified")
