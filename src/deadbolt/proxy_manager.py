"""Root-owned lifecycle of one approved, loopback-only SSH interception service."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import time
from typing import Callable

from deadbolt.outbound import OutboundPolicy


class ProxyError(RuntimeError):
    pass


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=60, check=False, shell=False)


class ProxyManager:
    UNIT = "deadbolt-ssh-proxy.service"
    LEASE = Path("/run/deadbolt/ssh-proxy/lease.json")

    def __init__(self, runner: Runner = _run, lease_path: Path = LEASE):
        self.runner = runner
        self.lease_path = lease_path

    def _systemctl(self, *args: str) -> str:
        try:
            result = self.runner(["/usr/bin/systemctl", *args, self.UNIT])
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProxyError("SSH proxy service command unavailable") from exc
        if result.returncode and not (args == ("is-active",) and result.stdout.strip() in ("inactive", "failed")):
            raise ProxyError("SSH proxy service command failed")
        return result.stdout.strip()

    def _read(self) -> dict[str, object] | None:
        try:
            info = self.lease_path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o027:
            raise ProxyError("SSH proxy lease has unsafe ownership or mode")
        try:
            value = json.loads(self.lease_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProxyError("SSH proxy lease is unreadable") from exc
        if not isinstance(value, dict):
            raise ProxyError("SSH proxy lease is invalid")
        return value

    def _write(self, value: dict[str, object]) -> None:
        parent = self.lease_path.parent
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o027:
            raise ProxyError("SSH proxy lease directory is unsafe")
        existing = self._read()
        if existing is not None and existing.get("request_id") != value["request_id"]:
            raise ProxyError("another approved SSH proxy grant is active")
        proxy_gid = pwd.getpwnam("deadbolt-ssh-proxy").pw_gid
        tmp = parent / (".lease-" + str(os.getpid()))
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o640)
        try:
            os.fchown(fd, 0, proxy_gid)
            data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.lease_path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def activate(self, policy: OutboundPolicy, canonical: dict[str, object],
                 request_id: str, expiry: int) -> dict[str, object]:
        if canonical["kind"] != "ssh" or expiry <= time.time():
            raise ProxyError("SSH proxy grant is invalid or expired")
        proxy_uid = pwd.getpwnam("deadbolt-ssh-proxy").pw_uid
        proxy_gid = pwd.getpwnam("deadbolt-ssh-proxy").pw_gid
        spool_info = Path(policy.spool_dir).stat()
        if (not stat.S_ISDIR(spool_info.st_mode) or spool_info.st_uid != proxy_uid
                or spool_info.st_mode & 0o077):
            raise ProxyError("SSH evidence spool is not private or available")
        for path, private in ((policy.proxy_host_key, True),
                              (canonical["ssh_key"], True),
                              (policy.hermes_client_key, False)):
            file_path = Path(path)
            info = file_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022
                    or private and (info.st_gid != proxy_gid or
                                    stat.S_IMODE(info.st_mode) != 0o640)):
                raise ProxyError("SSH proxy credential has unsafe ownership or mode")
            for parent in file_path.parents:
                parent_info = parent.lstat()
                if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
                        or parent_info.st_mode & 0o022):
                    raise ProxyError("SSH proxy credential directory is unsafe")
        exporter = self.runner(["/usr/bin/systemctl", "is-active", "deadbolt-ssh-exporter.service"])
        if exporter.returncode or exporter.stdout.strip() != "active":
            raise ProxyError("restricted SSH evidence exporter is not active")
        lease: dict[str, object] = {"request_id": request_id, "expires_at": expiry,
            "destination": canonical["destination"], "port": canonical["port"],
            "ssh_user": canonical["ssh_user"], "ssh_key": canonical["ssh_key"],
            "target_host_fingerprint": canonical["target_host_fingerprint"],
            "proxy_port": policy.proxy_port, "proxy_host_key": policy.proxy_host_key,
            "hermes_client_key": policy.hermes_client_key, "spool_dir": policy.spool_dir}
        self._write(lease)
        self._systemctl("start")
        if self._systemctl("is-active") != "active":
            raise ProxyError("SSH proxy did not become active")
        if self._read() != lease:
            raise ProxyError("SSH proxy lease changed during activation")
        return {"proxy_host": "127.0.0.1", "proxy_port": policy.proxy_port}

    def revoke(self, request_id: str) -> None:
        lease = self._read()
        if lease is not None:
            if lease.get("request_id") != request_id:
                raise ProxyError("SSH proxy lease belongs to another request")
            self.lease_path.unlink()
        # Stopping the service closes every transport, including idle sessions.
        self._systemctl("stop")
        if self._read() is not None or self._systemctl("is-active") == "active":
            raise ProxyError("SSH proxy remained active after revocation")

    def assert_active(self, request_id: str, expiry: int) -> None:
        lease = self._read()
        if (lease is None or lease.get("request_id") != request_id
                or lease.get("expires_at") != expiry or expiry <= time.time()
                or self._systemctl("is-active") != "active"):
            raise ProxyError("SSH proxy is not active for the approved grant")


def expire_lease(manager: ProxyManager, now: float = 0) -> bool:
    """Independent systemd timer entry point; a missing lease is idempotent."""
    lease = manager._read()
    if lease is None:
        return False
    instant = now or time.time()
    expiry = lease.get("expires_at")
    if type(expiry) is not int:
        raise ProxyError("invalid SSH proxy expiry")
    if instant < expiry:
        return False
    manager.revoke(str(lease["request_id"]))
    return True


def expiry_main() -> None:
    expire_lease(ProxyManager())
