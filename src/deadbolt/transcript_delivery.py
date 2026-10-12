"""Mutually authenticated, checksummed transfer to Argus restricted evidence.

The Hermes exporter reads only completed local sessions. Argus acknowledges a
manifest only after both the root-only transcript and restricted Loki entries
have been durably accepted. Retries are idempotent by session ID and digest.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import logging
import os
from pathlib import Path
import pwd
import re
import ssl
import stat
import time
from typing import Any
import urllib.request
import uuid

from deadbolt.ssh_transcript import EvidenceError, MAX_SESSION_BYTES, _write_all, recover_orphans


LOG = logging.getLogger(__name__)
ARGUS_TRANSCRIPTS = Path("/srv/argus/deadbolt/ssh-transcripts")
MAX_TRANSCRIPT_BYTES = MAX_SESSION_BYTES
MAX_LOKI_BATCH_BYTES = 512 * 1024


class DeliveryError(RuntimeError):
    pass


def _private_directory(path: Path, owner_uid: int | None = None) -> None:
    info = path.lstat()
    expected = os.geteuid() if owner_uid is None else owner_uid
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected or info.st_mode & 0o077:
        raise DeliveryError("restricted transcript directory is not private")


def _private_file(path: Path, owner_uid: int) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or info.st_mode & 0o177):
        raise DeliveryError("restricted transcript file has unsafe ownership or mode")


def _validate_manifest(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) - {
            "session_id", "request_id", "frame_count", "sha256", "finished_at", "reason",
            "output_incomplete", "partial_frame"}
            or not all(key in value for key in ("session_id", "request_id", "frame_count", "sha256"))):
        raise DeliveryError("invalid SSH evidence manifest")
    for key in ("session_id", "request_id"):
        try:
            valid = isinstance(value[key], str) and str(uuid.UUID(value[key])) == value[key]
        except ValueError:
            valid = False
        if not valid:
            raise DeliveryError("invalid SSH evidence identity")
    if not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise DeliveryError("invalid SSH evidence checksum")
    if type(value["frame_count"]) is not int or value["frame_count"] < 1:
        raise DeliveryError("invalid SSH evidence frame count")
    if value.get("reason", "complete") not in (
            "complete", "expired", "emergency_stop", "proxy_failure",
            "evidence_failure", "revoked", "proxy_crash"):
        raise DeliveryError("invalid SSH evidence completion reason")
    if "output_incomplete" in value and type(value["output_incomplete"]) is not bool:
        raise DeliveryError("invalid SSH evidence completion state")
    if "partial_frame" in value and type(value["partial_frame"]) is not bool:
        raise DeliveryError("invalid SSH evidence partial-frame state")
    if value.get("partial_frame") and (value.get("reason") != "proxy_crash"
                                       or value.get("output_incomplete") is not True):
        raise DeliveryError("partial SSH evidence must be marked as a proxy crash")
    return value


def _manifest(path: Path) -> dict[str, Any]:
    try:
        return _validate_manifest(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise DeliveryError("SSH evidence manifest is unreadable") from exc


class TranscriptExporter:
    def __init__(self, spool: Path, host: str, port: int, ca: Path,
                 client_cert: Path, client_key: Path, *, proxy_uid: int | None = None):
        self.spool = spool
        self.proxy_uid = (pwd.getpwnam("deadbolt-ssh-proxy").pw_uid
                          if proxy_uid is None else proxy_uid)
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(cafile=str(ca))
        self.context.load_cert_chain(str(client_cert), str(client_key))
        self.context.check_hostname = True

    def deliver_one(self, directory: Path) -> bool:
        _private_directory(directory, self.proxy_uid)
        manifest_file = directory / "manifest.json"
        if not manifest_file.is_file():
            return False
        _private_file(manifest_file, self.proxy_uid)
        manifest = _manifest(manifest_file)
        if directory.name != manifest["session_id"]:
            raise DeliveryError("session directory differs from manifest")
        marker = directory / "delivered.json"
        if marker.exists():
            _private_file(marker, os.geteuid())
            try:
                existing = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise DeliveryError("restricted delivery marker is unreadable") from exc
            if existing != {
                    "session_id": manifest["session_id"], "sha256": manifest["sha256"], "ack": True}:
                raise DeliveryError("restricted delivery marker does not match transcript")
            return False
        frames = directory / "frames.jsonl"
        _private_file(frames, self.proxy_uid)
        size = frames.stat().st_size
        if size < 1 or size > MAX_TRANSCRIPT_BYTES:
            raise DeliveryError("SSH transcript exceeds receiver policy")
        digest = hashlib.sha256()
        with frames.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != manifest["sha256"]:
            raise DeliveryError("local SSH transcript checksum mismatch")
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=60)
        try:
            conn.putrequest("PUT", f"/v1/transcripts/{manifest['session_id']}")
            conn.putheader("Content-Type", "application/x-ndjson")
            conn.putheader("Content-Length", str(size))
            conn.putheader("X-Deadbolt-Manifest",
                           base64.b64encode(json.dumps(manifest, sort_keys=True).encode()).decode())
            conn.endheaders()
            with frames.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    conn.send(chunk)
            response = conn.getresponse()
            raw = response.read(4096)
            if response.status != 200:
                raise DeliveryError("Argus restricted receiver did not acknowledge transcript")
            ack = json.loads(raw)
            if ack != {"session_id": manifest["session_id"], "sha256": manifest["sha256"], "ack": True}:
                raise DeliveryError("Argus restricted receiver acknowledgment mismatch")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise DeliveryError("Argus restricted evidence delivery failed") from exc
        finally:
            conn.close()
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            _write_all(fd, (json.dumps(ack, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return True

    def once(self) -> tuple[int, int]:
        _private_directory(self.spool, self.proxy_uid)
        try:
            recovered = recover_orphans(self.spool, owner_uid=self.proxy_uid)
            if recovered:
                LOG.warning("recovered %d crashed SSH transcript sessions for restricted delivery", recovered)
        except EvidenceError:
            # A malformed or partial frame remains on disk for inspection;
            # complete sessions must still be delivered on this pass.
            LOG.exception("crashed SSH transcript recovery needs inspection")
        delivered = 0
        pending = 0
        for directory in sorted(self.spool.iterdir()):
            if not directory.is_dir() or not (directory / "manifest.json").exists():
                continue
            pending += 1
            try:
                if self.deliver_one(directory):
                    delivered += 1
                else:
                    pending -= 1
            except (DeliveryError, EvidenceError, OSError, ValueError):
                LOG.exception("restricted SSH transcript delivery is backlogged: %s", directory.name)
        if pending > delivered:
            LOG.error("restricted SSH evidence backlog: %d sessions awaiting Argus acknowledgment",
                      pending - delivered)
        return delivered, pending - delivered


def _loki_lines(raw: bytes, manifest: dict[str, Any]) -> list[list[str]]:
    lines = []
    last_ns = 0
    last_event = None
    for sequence, payload in enumerate(raw.splitlines()):
        try:
            frame = json.loads(payload)
        except ValueError:
            if (sequence != manifest["frame_count"] - 1
                    or not manifest.get("partial_frame")
                    or not manifest.get("output_incomplete")):
                raise DeliveryError("SSH transcript contains a malformed frame")
            # The raw Argus file retains these exact bytes; the restricted
            # searchable stream labels the final fragment explicitly.
            frame = {"session_id": manifest["session_id"],
                     "request_id": manifest["request_id"], "sequence": sequence,
                     "timestamp": manifest["finished_at"], "event": "recovery_tail",
                     "data_b64": base64.b64encode(payload).decode(),
                     "metadata": {"partial_frame": True}}
        if (frame.get("session_id") != manifest["session_id"]
                or frame.get("request_id") != manifest["request_id"]
                or frame.get("sequence") != sequence
                or frame.get("event") not in {"session_started", "stdin", "stdout", "stderr",
                                              "exec_request", "session_finished", "session_failed",
                                              "recovery_tail"}
                or frame.get("event") == "recovery_tail" and
                   (sequence != manifest["frame_count"] - 1 or not manifest.get("partial_frame"))
                or sequence == 0 and frame.get("event") != "session_started"):
            raise DeliveryError("SSH transcript frame identity or order mismatch")
        last_event = frame["event"]
        data = base64.b64decode(frame["data_b64"], validate=True)
        # The restricted tenant may contain credentials by design. Encode
        # control bytes visibly so one SSH frame remains one Loki line.
        text = data.decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii")
        stamp = datetime.strptime(frame["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        ns = max(last_ns + 1, int(stamp.timestamp() * 1_000_000_000))
        last_ns = ns
        item = {"session_id": manifest["session_id"], "request_id": manifest["request_id"],
                "sequence": sequence, "event": frame["event"], "text": text,
                "metadata": frame.get("metadata", {})}
        lines.append([str(ns), json.dumps(item, sort_keys=True, separators=(",", ":"))])
    if len(lines) != manifest["frame_count"]:
        raise DeliveryError("SSH transcript frame count mismatch")
    if (not manifest.get("output_incomplete") and
            last_event not in ("session_finished", "session_failed")):
        raise DeliveryError("SSH transcript has no completion frame")
    return lines


class ArgusReceiver:
    def __init__(self, root: Path, loki_url: str, tenant: str):
        _private_directory(root)
        if not re.fullmatch(r"[a-z0-9-]{1,64}", tenant):
            raise DeliveryError("invalid restricted Loki tenant")
        if (not re.fullmatch(r"https?://[A-Za-z0-9_.:-]+/loki/api/v1/push", loki_url)
                or loki_url == "http://127.0.0.1:3100/loki/api/v1/push"):
            raise DeliveryError("a dedicated restricted Loki endpoint is required")
        self.root = root
        self.tenant = tenant
        self.loki_url = loki_url

    def store(self, session_id: str, body: bytes, manifest: dict[str, Any]) -> dict[str, Any]:
        manifest = _validate_manifest(manifest)
        if (str(uuid.UUID(session_id)) != session_id or session_id != manifest["session_id"]
                or not 1 <= len(body) <= MAX_TRANSCRIPT_BYTES
                or hashlib.sha256(body).hexdigest() != manifest["sha256"]):
            raise DeliveryError("restricted transcript identity or checksum mismatch")
        lines = _loki_lines(body, manifest)
        directory = self.root / session_id
        directory.mkdir(mode=0o700, exist_ok=True)
        _private_directory(directory)
        frames = directory / "frames.jsonl"
        if frames.exists():
            if hashlib.sha256(frames.read_bytes()).hexdigest() != manifest["sha256"]:
                raise DeliveryError("existing Argus transcript has a different checksum")
        else:
            fd = os.open(frames, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                _write_all(fd, body)
                os.fsync(fd)
            finally:
                os.close(fd)
        manifest_file = directory / "manifest.json"
        if not manifest_file.exists():
            fd = os.open(manifest_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                _write_all(fd, (json.dumps(manifest, sort_keys=True) + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
        marker = directory / "loki-delivered"
        if not marker.exists():
            labels = {"source": "deadbolt-ssh-restricted", "session_id": session_id,
                      "request_id": manifest["request_id"]}
            batch: list[list[str]] = []
            batch_bytes = 0
            def send_batch() -> None:
                payload = {"streams": [{"stream": labels, "values": batch}]}
                request = urllib.request.Request(self.loki_url,
                    data=json.dumps(payload, separators=(",", ":")).encode(),
                    headers={"Content-Type": "application/json", "X-Scope-OrgID": self.tenant},
                    method="POST")
                try:
                    with urllib.request.urlopen(request, timeout=30) as response:
                        if response.status != 204:
                            raise DeliveryError("restricted Loki ingestion failed")
                except OSError as exc:
                    raise DeliveryError("restricted Loki ingestion failed") from exc
            for line in lines:
                length = len(line[1].encode("utf-8")) + 128
                if batch and batch_bytes + length > MAX_LOKI_BATCH_BYTES:
                    send_batch()
                    batch = []
                    batch_bytes = 0
                batch.append(line)
                batch_bytes += length
            if batch:
                send_batch()
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.fsync(fd)
            os.close(fd)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return {"session_id": session_id, "sha256": manifest["sha256"], "ack": True}


def receiver_handler(receiver: ArgusReceiver):
    class Handler(BaseHTTPRequestHandler):
        def do_PUT(self):
            match = re.fullmatch(r"/v1/transcripts/([0-9a-f-]{36})", self.path)
            try:
                if match is None:
                    raise DeliveryError("unknown restricted receiver path")
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= MAX_TRANSCRIPT_BYTES:
                    raise DeliveryError("invalid restricted transcript size")
                encoded = self.headers.get("X-Deadbolt-Manifest", "")
                if len(encoded) > 4096:
                    raise DeliveryError("restricted manifest is too large")
                manifest = json.loads(base64.b64decode(encoded, validate=True))
                body = self.rfile.read(length)
                if len(body) != length:
                    raise DeliveryError("restricted transcript upload is incomplete")
                ack = receiver.store(match[1], body, manifest)
            except (ValueError, KeyError, DeliveryError, EvidenceError, OSError) as exc:
                LOG.warning("restricted transcript not acknowledged: %s", type(exc).__name__)
                self.send_error(422, "restricted transcript rejected")
                return
            payload = json.dumps(ack, sort_keys=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            del format, args  # Never copy transcript data into ordinary logs.

    return Handler


def receiver_main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--client-ca", type=Path, required=True)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--loki-url", required=True,
                        help="dedicated restricted Loki ingestion endpoint")
    parser.add_argument("--loki-tenant", required=True,
                        help="restricted Loki tenant with separate access controls")
    args = parser.parse_args()
    receiver = ArgusReceiver(ARGUS_TRANSCRIPTS, args.loki_url, args.loki_tenant)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(str(args.cert), str(args.key))
    context.load_verify_locations(str(args.client_ca))
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer((args.listen, args.port), receiver_handler(receiver))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def exporter_main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    exporter = TranscriptExporter(args.spool, args.host, args.port, args.ca, args.cert, args.key)
    while True:
        exporter.once()
        time.sleep(10)
