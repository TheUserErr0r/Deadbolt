"""Byte-exact, fsync-before-forward SSH evidence spool.

The session file contains newline-delimited frames. Data are base64 because SSH
streams can contain arbitrary bytes. A final manifest binds every byte with a
SHA-256 digest. No frame is forwarded until its write and fsync have succeeded.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
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
        os.close(self.fd)
        self.closed = True
        manifest_path = self.path / "manifest.json"
        fd = os.open(manifest_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            _write_all(fd, (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(self.path, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return manifest


def recover_orphans(base: Path) -> int:
    """Complete sessions left open by a prior crashed proxy process."""
    recovered = 0
    for directory in base.iterdir():
        if not directory.is_dir() or (directory / "manifest.json").exists():
            continue
        try:
            session_id = str(uuid.UUID(directory.name))
        except ValueError:
            continue
        if session_id != directory.name:
            continue
        frames = directory / "frames.jsonl"
        if not frames.is_file():
            continue
        payload = frames.read_bytes()
        if payload and not payload.endswith(b"\n"):
            # An incomplete last frame must be surfaced, never hidden.
            raise EvidenceError("crashed SSH transcript contains a partial frame")
        lines = payload.splitlines()
        if not lines:
            raise EvidenceError("crashed SSH transcript has no start event")
        try:
            first = json.loads(lines[0])
        except ValueError as exc:
            raise EvidenceError("crashed SSH transcript is malformed") from exc
        manifest = {"session_id": session_id, "request_id": first["request_id"],
                    "frame_count": len(lines), "sha256": hashlib.sha256(payload).hexdigest(),
                    "finished_at": _utc(), "reason": "proxy_crash", "output_incomplete": True}
        fd = os.open(directory / "manifest.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            _write_all(fd, (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        recovered += 1
    return recovered
