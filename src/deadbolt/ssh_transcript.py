"""Byte-exact, fsync-before-forward SSH evidence spool.

The session file contains newline-delimited frames. Data are base64 because SSH
streams can contain arbitrary bytes. A final manifest binds every byte with a
SHA-256 digest. No frame is forwarded until its write and fsync have succeeded.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid
from typing import Any


class EvidenceError(RuntimeError):
    pass


MIN_FREE_BYTES = 64 * 1024 * 1024
MAX_SESSION_BYTES = 32 * 1024 * 1024


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_all(fd: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        n = os.write(fd, remaining)
        if n <= 0:
            raise EvidenceError("evidence write made no progress")
        remaining = remaining[n:]


def _commit_manifest(directory: Path, manifest: dict[str, Any], owner: int) -> None:
    """Publish a complete manifest while the session writer lock is held."""
    temporary = directory / f".manifest-{uuid.uuid4()}.tmp"
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        try:
            if os.geteuid() != owner:
                os.fchown(fd, owner, -1)
            _write_all(fd, (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temporary, directory / "manifest.json", follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    directory_fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


class TranscriptSpool:
    def __init__(self, base: Path, request_id: str, destination: str, port: int,
                 ssh_user: str, *, session_id: str | None = None):
        self.session_id = session_id or str(uuid.uuid4())
        if str(uuid.UUID(self.session_id)) != self.session_id:
            raise EvidenceError("invalid session ID")
        info = base.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise EvidenceError("SSH evidence spool is not private")
        self.path = base / self.session_id
        self.path.mkdir(mode=0o700)
        self.fd = os.open(self.path / "frames.jsonl",
                          os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            # The exporter can distinguish a live writer from a crashed one
            # without waiting for another proxy process to start.
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.fd)
            raise EvidenceError("SSH evidence writer lock is unavailable") from exc
        self.digest = hashlib.sha256()
        self.count = 0
        self.bytes_written = 0
        self.closed = False
        self.request_id = request_id
        self.record("session_started", metadata={"destination": destination, "port": port,
                                                 "ssh_user": ssh_user})

    def record(self, event: str, data: bytes = b"", *, metadata: dict[str, Any] | None = None) -> None:
        if self.closed or event not in {"session_started", "stdin", "stdout", "stderr",
                                        "exec_request", "session_finished", "session_failed"}:
            raise EvidenceError("invalid SSH evidence event")
        if not isinstance(data, bytes) or len(data) > 65536:
            raise EvidenceError("SSH evidence chunk exceeds fixed boundary")
        disk = os.statvfs(self.path)
        if disk.f_bavail * disk.f_frsize < MIN_FREE_BYTES:
            raise EvidenceError("SSH evidence spool is full")
        frame = {"session_id": self.session_id, "request_id": self.request_id,
                 "sequence": self.count, "timestamp": _utc(), "event": event,
                 "data_b64": base64.b64encode(data).decode("ascii"),
                 "metadata": metadata or {}}
        payload = (json.dumps(frame, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if self.bytes_written + len(payload) > MAX_SESSION_BYTES - 4096:
            raise EvidenceError("SSH evidence session reached its explicit size limit")
        try:
            _write_all(self.fd, payload)
            os.fsync(self.fd)
        except OSError as exc:
            raise EvidenceError("SSH evidence could not be persisted") from exc
        self.digest.update(payload)
        self.bytes_written += len(payload)
        self.count += 1

    def finish(self, reason: str = "complete") -> dict[str, Any]:
        if self.closed:
            raise EvidenceError("SSH evidence session already closed")
        if reason not in ("complete", "expired", "emergency_stop", "proxy_failure",
                          "evidence_failure", "revoked"):
            raise EvidenceError("invalid SSH session end reason")
        self.record("session_finished" if reason == "complete" else "session_failed",
                    metadata={"reason": reason})
        manifest = {"session_id": self.session_id, "request_id": self.request_id,
                    "frame_count": self.count, "sha256": self.digest.hexdigest(),
                    "finished_at": _utc(), "reason": reason}
        try:
            _commit_manifest(self.path, manifest, os.geteuid())
        finally:
            os.close(self.fd)
            self.closed = True
        return manifest


def recover_orphans(base: Path, *, owner_uid: int | None = None) -> int:
    """Complete unlocked sessions left by crashed proxies, even without a new grant."""
    owner = os.geteuid() if owner_uid is None else owner_uid
    info = base.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
        raise EvidenceError("SSH evidence spool is not private")
    recovered = 0
    first_error: EvidenceError | None = None
    for directory in base.iterdir():
        try:
            session_id = str(uuid.UUID(directory.name))
        except ValueError:
            continue
        if session_id != directory.name:
            continue
        try:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
                raise EvidenceError("crashed SSH transcript directory is unsafe")
            if (directory / "manifest.json").exists():
                continue
            frames = directory / "frames.jsonl"
            frame_info = frames.lstat()
            if (not stat.S_ISREG(frame_info.st_mode) or frame_info.st_uid != owner
                    or frame_info.st_mode & 0o077):
                raise EvidenceError("crashed SSH transcript file is unsafe")
            fd = os.open(frames, os.O_RDONLY | os.O_NOFOLLOW)
        except (OSError, EvidenceError) as exc:
            if first_error is None:
                first_error = EvidenceError("crashed SSH transcript cannot be inspected")
                first_error.__cause__ = exc
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue  # An active proxy still owns this session.
            if (directory / "manifest.json").exists():
                continue
            with os.fdopen(os.dup(fd), "rb") as stream:
                payload = stream.read(MAX_SESSION_BYTES + 1)
            if len(payload) > MAX_SESSION_BYTES:
                raise EvidenceError("crashed SSH transcript exceeds its size limit")
            partial_frame = bool(payload and not payload.endswith(b"\n"))
            lines = payload.splitlines()
            if not lines:
                raise EvidenceError("crashed SSH transcript has no start event")
            try:
                first = json.loads(lines[0])
                request_id = str(uuid.UUID(first["request_id"]))
            except (ValueError, KeyError, TypeError) as exc:
                raise EvidenceError("crashed SSH transcript is malformed") from exc
            if (first.get("session_id") != session_id or first.get("event") != "session_started"
                    or request_id != first["request_id"]):
                raise EvidenceError("crashed SSH transcript start event is invalid")
            manifest = {"session_id": session_id, "request_id": request_id,
                        "frame_count": len(lines), "sha256": hashlib.sha256(payload).hexdigest(),
                        "finished_at": _utc(), "reason": "proxy_crash",
                        "output_incomplete": True, "partial_frame": partial_frame}
            _commit_manifest(directory, manifest, owner)
            recovered += 1
        except (OSError, EvidenceError) as exc:
            if first_error is None:
                first_error = EvidenceError("crashed SSH transcript recovery failed")
                first_error.__cause__ = exc
        finally:
            os.close(fd)
    if first_error is not None:
        raise first_error
    return recovered
