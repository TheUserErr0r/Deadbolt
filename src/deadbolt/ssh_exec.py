"""Bounded noninteractive SSH transport to a fixed remote argv receiver."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable

from deadbolt.access import AccessError, SENSITIVE, command_argv


MAX_OUTPUT_BYTES = 65536  # Per stdout/stderr stream; excess is drained and flagged.
MAX_ROOT_RESULT_BYTES = 262144
MAX_EXECUTION_SECONDS = 60
REMOTE_RECEIVER = "/usr/local/libexec/deadbolt-remote-exec"


def redact(value: str) -> str:
    value = re.sub(r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*\S+",
                   lambda match: match.group(1) + "=[REDACTED]", value)
    value = re.sub(r"(?i)\b(?:https?://)\S+", "[URL REDACTED]", value)
    return value


def _safe_root_file(path: str, *, broker_uid: int, broker_gid: int, private: bool) -> None:
    item = Path(path)
    if not item.is_absolute() or item.is_symlink():
        raise AccessError("unsafe SSH profile file")
    info = item.stat()
    parent = item.parent.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, broker_uid)
            or info.st_gid != broker_gid or info.st_mode & 0o027
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022
            or (private and info.st_mode & 0o007)):
        raise AccessError("unsafe SSH profile file")


def _bounded_run(argv: list[str], payload: bytes, timeout: float,
                 max_output_bytes: int = MAX_OUTPUT_BYTES) -> tuple[int, str, str]:
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, close_fds=True,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    assert process.stdin and process.stdout and process.stderr
    deadline = time.monotonic() + timeout
    stdout_fd, stderr_fd = process.stdout.fileno(), process.stderr.fileno()
    output = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    data = memoryview(payload)
    selector = selectors.DefaultSelector()
    try:
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("SSH execution deadline exceeded")
            for key, _events in selector.select(remaining):
                if key.fileobj is process.stdin:
                    try:
                        written = os.write(process.stdin.fileno(), data[:4096]) if data else 0
                    except BrokenPipeError:
                        written = 0
                    data = data[written:]
                    if not data or not written:
                        selector.unregister(process.stdin)
                        process.stdin.close()
                else:
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    output[key.fd].extend(chunk)
                    if len(output[key.fd]) > max_output_bytes:
                        raise AccessError("SSH output limit exceeded")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SSH execution deadline exceeded")
        code = process.wait(timeout=remaining)
        return code, output[stdout_fd].decode("utf-8", "replace"), output[stderr_fd].decode("utf-8", "replace")
    except Exception:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()


@dataclass(frozen=True)
class CaptureResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool


def _capture_run(argv: list[str], payload: bytes, timeout: float) -> CaptureResult:
    """Capture exact bytes up to MAX_OUTPUT_BYTES per stream and keep draining."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, close_fds=True,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    assert process.stdin and process.stdout and process.stderr
    deadline = time.monotonic() + timeout
    stdout_fd, stderr_fd = process.stdout.fileno(), process.stderr.fileno()
    output = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    truncated = {stdout_fd: False, stderr_fd: False}
    data = memoryview(payload)
    selector = selectors.DefaultSelector()
    timed_out = False
    def append_chunk(fd: int, chunk: bytes) -> None:
        remaining_bytes = MAX_OUTPUT_BYTES - len(output[fd])
        output[fd].extend(chunk[:remaining_bytes])
        if len(chunk) > remaining_bytes:
            truncated[fd] = True

    try:
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _events in selector.select(remaining):
                if key.fileobj is process.stdin:
                    try:
                        written = os.write(process.stdin.fileno(), data[:4096]) if data else 0
                    except BrokenPipeError:
                        written = 0
                    data = data[written:]
                    if not data or not written:
                        selector.unregister(process.stdin)
                        process.stdin.close()
                else:
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    append_chunk(key.fd, chunk)
        if not timed_out:
            try:
                code = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
        if timed_out:
            process.kill()
            process.wait()
            for stream in (process.stdout, process.stderr):
                if stream.closed:
                    continue
                while chunk := os.read(stream.fileno(), 4096):
                    append_chunk(stream.fileno(), chunk)
            code = None
        return CaptureResult(code, bytes(output[stdout_fd]), bytes(output[stderr_fd]),
                             truncated[stdout_fd], truncated[stderr_fd], timed_out)
    except Exception:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()


Runner = Callable[[list[str], bytes, float], tuple[int, str, str]]


def _ssh_argv(record: dict[str, Any]) -> list[str]:
    return ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", "22", "-l", record["ssh_user"],
            "-i", record["ssh_key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "RequestTTY=no",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={record['known_hosts']}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none", "-o", f"HostKeyAlias={record['destination']}",
            "--", record["pinned_ip"], REMOTE_RECEIVER]


def run_child(record: dict[str, Any], runner: Callable[..., CaptureResult] = _capture_run,
              now: Callable[[], float] = time.time) -> dict[str, Any]:
    required = {"version", "request_id", "approval_id", "command_index", "destination",
                "pinned_ip", "ssh_user", "ssh_key", "known_hosts", "argv", "audit_output",
                "expires_at", "timeout_seconds"}
    if not isinstance(record, dict) or set(record) != required or record["version"] != 1:
        raise AccessError("invalid broker child request")
    if pwd.getpwuid(os.geteuid()).pw_name != "deadbolt-ssh":
        raise AccessError("SSH child must run as deadbolt-ssh")
    identity = pwd.getpwnam("deadbolt-ssh")
    _safe_root_file(record["ssh_key"], broker_uid=identity.pw_uid,
                    broker_gid=identity.pw_gid, private=True)
    _safe_root_file(record["known_hosts"], broker_uid=identity.pw_uid,
                    broker_gid=identity.pw_gid, private=False)
    if record["audit_output"] not in ("metadata", "full"):
        raise AccessError("invalid broker audit mode")
    command = command_argv(record["argv"], allow_sensitive=record["audit_output"] == "full")
    if (type(record["command_index"]) is not int or record["command_index"] < 1
            or type(record["timeout_seconds"]) is not int
            or not 1 <= record["timeout_seconds"] <= MAX_EXECUTION_SECONDS
            or type(record["expires_at"]) not in (int, float)
            or now() >= record["expires_at"]):
        raise AccessError("expired or invalid broker command")
    started = now()
    payload = (json.dumps({"version": 1, "argv": command}, separators=(",", ":")) + "\n").encode()
    captured = runner(_ssh_argv(record), payload,
                      min(record["timeout_seconds"], record["expires_at"] - started))
    mode = record["audit_output"]
    termination = ("timeout" if captured.timed_out else "signal"
                   if captured.exit_code is not None and captured.exit_code < 0 else "exit")
    return {"request_id": record["request_id"], "approval_id": record["approval_id"],
            "command_index": record["command_index"], "started_at": started,
            "finished_at": now(), "destination": record["destination"],
            "pinned_ip": record["pinned_ip"], "ssh_user": record["ssh_user"],
            "command": command if mode == "full" else [redact(part) for part in command],
            "exit_code": captured.exit_code, "termination": termination,
            "timed_out": captured.timed_out, "audit_output": mode,
            "stdout_b64": base64.b64encode(captured.stdout).decode("ascii") if mode == "full" else None,
            "stderr_b64": base64.b64encode(captured.stderr).decode("ascii") if mode == "full" else None,
            "stdout_truncated": captured.stdout_truncated,
            "stderr_truncated": captured.stderr_truncated}


class SystemdSSHExecutor:
    """Root launcher; a transient hardened unit executes SSH as deadbolt-ssh."""

    def __init__(self, credential_dir: Path = Path("/run/deadbolt/ssh-requests"),
                 runner: Callable[..., tuple[int, str, str]] = _bounded_run,
                 owner_uid: int = 0):
        self.credential_dir = credential_dir
        self.runner = runner
        self.owner_uid = owner_uid
        self._cancellations: dict[str, threading.Event] = {}
        self._cancellation_lock = threading.Lock()

    @staticmethod
    def _unit(request_id: str, command_index: int) -> str:
        try:
            valid = str(uuid.UUID(request_id)) == request_id
        except (TypeError, ValueError, AttributeError):
            valid = False
        if not valid or type(command_index) is not int or command_index < 1:
            raise AccessError("invalid SSH unit identity")
        return f"deadbolt-ssh-{request_id}-{command_index}.service"

    def cancel(self, request_id: str, command_index: int) -> None:
        """Preempt a known transient unit; safe before the worker starts it."""
        unit = self._unit(request_id, command_index)
        with self._cancellation_lock:
            event = self._cancellations.setdefault(unit, threading.Event())
            event.set()
        try:
            subprocess.run(["/usr/bin/systemctl", "stop", unit], shell=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
            state = subprocess.run(["/usr/bin/systemctl", "show", "--property=ActiveState",
                                    "--value", unit], shell=False, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AccessError("SSH unit cancellation failed") from exc
        if state.returncode or state.stdout.strip() not in ("inactive", "failed"):
            raise AccessError("SSH unit remained active after cancellation")

    def execute(self, canonical: dict[str, Any], request_id: str, approval_id: str,
                command_index: int, argv: list[str], active_until: float,
                now: float) -> dict[str, Any]:
        command = command_argv(argv, allow_sensitive=canonical["audit_output"] == "full")
        if command[0] not in canonical["remote_commands"]:
            raise AccessError("command is outside the root-owned receiver allow-list")
        if now >= active_until or canonical["protocol"] != "tcp" or canonical["ports"] != [22]:
            raise AccessError("SSH grant is expired or not TCP/22")
        if len(canonical["pinned_ips"]) != 1:
            raise AccessError("SSH requires one pinned IP")
        uuid.UUID(request_id)
        if type(command_index) is not int or not 1 <= command_index <= canonical["max_commands"]:
            raise AccessError("SSH command count exceeded")
        broker = pwd.getpwnam("deadbolt-ssh")
        _safe_root_file(canonical["ssh_key"], broker_uid=broker.pw_uid,
                        broker_gid=broker.pw_gid, private=True)
        _safe_root_file(canonical["known_hosts"], broker_uid=broker.pw_uid,
                        broker_gid=broker.pw_gid, private=False)
        limit = max(1, min(MAX_EXECUTION_SECONDS, int(active_until - now)))
        credential = {"version": 1, "request_id": request_id, "approval_id": approval_id,
                      "command_index": command_index, "destination": canonical["destination"],
                      "pinned_ip": canonical["pinned_ips"][0], "ssh_user": canonical["ssh_user"],
                      "ssh_key": canonical["ssh_key"], "known_hosts": canonical["known_hosts"],
                      "argv": command, "audit_output": canonical["audit_output"],
                      "expires_at": active_until, "timeout_seconds": limit}
        self.credential_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.credential_dir.is_symlink():
            raise AccessError("unsafe broker credential directory")
        directory = self.credential_dir.stat()
        if directory.st_uid != self.owner_uid or directory.st_mode & 0o077:
            raise AccessError("unsafe broker credential directory")
        path = self.credential_dir / f"{request_id}-{command_index}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            payload = (json.dumps(credential, separators=(",", ":")) + "\n").encode()
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        unit = self._unit(request_id, command_index)
        with self._cancellation_lock:
            cancelled = self._cancellations.setdefault(unit, threading.Event())
        if cancelled.is_set():
            path.unlink(missing_ok=True)
            raise AccessError("SSH command was cancelled")
        address = canonical["pinned_ips"][0]
        prefix = "128" if ":" in address else "32"
        properties = ["User=deadbolt-ssh", "Group=deadbolt-ssh", "NoNewPrivileges=yes",
                      "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes",
                      "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
                      "ProtectControlGroups=yes", "PrivateDevices=yes",
                      "LockPersonality=yes", "RestrictSUIDSGID=yes",
                      "CapabilityBoundingSet=", "AmbientCapabilities=",
                      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                      "IPAddressDeny=any", f"IPAddressAllow={address}/{prefix}",
                      f"RuntimeMaxSec={limit}s", "TimeoutStopSec=5s",
                      f"LoadCredential=request:{path}"]
        command_line = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
                        f"--unit={unit}", *(f"--property={item}" for item in properties),
                        "/opt/deadbolt/venv/bin/deadbolt-ssh-child"]
        try:
            if cancelled.is_set():
                raise AccessError("SSH command was cancelled")
            status, stdout, _stderr = self.runner(command_line, b"", limit + 10,
                                                   MAX_ROOT_RESULT_BYTES)
        finally:
            path.unlink(missing_ok=True)
            with self._cancellation_lock:
                self._cancellations.pop(unit, None)
        if cancelled.is_set():
            raise AccessError("SSH command was cancelled")
        if status != 0 or stdout.count("\n") != 1 or len(stdout) > MAX_ROOT_RESULT_BYTES:
            raise AccessError("broker unit failed or returned invalid result")
        try:
            result = json.loads(stdout)
        except ValueError as exc:
            raise AccessError("invalid broker unit result") from exc
        if (not isinstance(result, dict) or set(result) != {"request_id", "approval_id", "command_index",
                "started_at", "finished_at", "destination", "pinned_ip", "ssh_user", "command",
                "exit_code", "termination", "timed_out", "audit_output", "stdout_b64",
                "stderr_b64", "stdout_truncated", "stderr_truncated"}
                or result["request_id"] != request_id or result["approval_id"] != approval_id
                or result["command_index"] != command_index or result["pinned_ip"] != address
                or result["destination"] != canonical["destination"]
                or result["ssh_user"] != canonical["ssh_user"]
                or result["audit_output"] != canonical["audit_output"]
                or result["command"] != (command if canonical["audit_output"] == "full"
                    else [redact(part) for part in command])
                or type(result["timed_out"]) is not bool
                or type(result["stdout_truncated"]) is not bool
                or type(result["stderr_truncated"]) is not bool
                or result["termination"] not in ("exit", "signal", "timeout")
                or (result["exit_code"] is None) != result["timed_out"]
                or (result["exit_code"] is not None and type(result["exit_code"]) is not int)
                or (result["timed_out"] != (result["termination"] == "timeout"))
                or (not result["timed_out"] and result["termination"] !=
                    ("signal" if result["exit_code"] < 0 else "exit"))
                or type(result["started_at"]) not in (int, float)
                or type(result["finished_at"]) not in (int, float)
                or not now - 2 <= result["started_at"] <= result["finished_at"] <= active_until + 2):
            raise AccessError("broker unit result does not match approved command")
        if canonical["audit_output"] == "metadata" and (result["stdout_b64"] is not None
                or result["stderr_b64"] is not None):
            raise AccessError("broker returned output despite metadata-only policy")
        if canonical["audit_output"] == "full":
            for field in ("stdout_b64", "stderr_b64"):
                if not isinstance(result[field], str):
                    raise AccessError("broker output violates full evidence contract")
                try:
                    size = len(base64.b64decode(result[field], validate=True))
                except (ValueError, base64.binascii.Error) as exc:
                    raise AccessError("invalid broker output encoding") from exc
                if size > MAX_OUTPUT_BYTES:
                    raise AccessError("broker output exceeds policy")
        return result


def child_main() -> None:
    try:
        directory = Path(os.environ["CREDENTIALS_DIRECTORY"])
        with (directory / "request").open("rb") as stream:
            raw = stream.read(3073)
        if len(raw) > 3072:
            raise AccessError("oversized broker credential")
        result = run_child(json.loads(raw))
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    except (AccessError, OSError, ValueError, KeyError):
        sys.stderr.write("broker child failed\n")
        raise SystemExit(1)
