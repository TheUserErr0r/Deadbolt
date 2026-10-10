"""Canonical requests, transactional transitions, and durable audit outbox."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
import uuid
from typing import Any


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class StateError(ValueError):
    pass


class Store:
    def __init__(self, path: Path, audit_path: Path, pending_ttl_seconds: int = 600):
        self.audit_path = audit_path
        self.pending_ttl_seconds = pending_ttl_seconds
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, action TEXT NOT NULL,
                profile TEXT NOT NULL, reason TEXT NOT NULL, requested_by_uid INTEGER NOT NULL,
                canonical_json TEXT NOT NULL, canonical_hash TEXT NOT NULL,
                description TEXT NOT NULL, nonce TEXT NOT NULL,
                created_at REAL NOT NULL, pending_until REAL NOT NULL,
                posted_message_id TEXT, approved_by_discord_id TEXT,
                interaction_id TEXT, approved_at REAL, active_until REAL,
                rollback_json TEXT, last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_outbox (
                id TEXT PRIMARY KEY, request_id TEXT NOT NULL, payload TEXT NOT NULL,
                flushed INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            );
            CREATE INDEX IF NOT EXISTS requests_status ON requests(status);
            CREATE INDEX IF NOT EXISTS audit_unflushed ON audit_outbox(flushed);
        """)

    def close(self) -> None:
        self.db.close()

    def _event(self, request_id: str, event: str, now: float, **fields: object) -> None:
        record = {"event_id": str(uuid.uuid4()), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                  "request_id": request_id, "event": event, **fields}
        self.db.execute("INSERT INTO audit_outbox(id,request_id,payload) VALUES(?,?,?)",
                        (record["event_id"], request_id, canonical_json(record)))

    def get(self, request_id: str) -> sqlite3.Row:
        try:
            uuid.UUID(request_id)
        except (ValueError, AttributeError) as exc:
            raise StateError("invalid request ID") from exc
        row = self.db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise StateError("unknown request")
        return row

    def create(self, canonical: dict[str, Any], description: str, requested_by_uid: int, now: float) -> sqlite3.Row:
        request_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(18)
        serialized = canonical_json(canonical)
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        deadline = now + self.pending_ttl_seconds
        card = (f"Request ID: {request_id}\n"
                f"Approval expires: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(deadline))}\n"
                f"{description}")
        with self.db:
            open_count = self.db.execute("SELECT COUNT(*) FROM requests WHERE status IN ('pending','posted')").fetchone()[0]
            if open_count >= 50:
                raise StateError("too many open requests")
            self.db.execute("""INSERT INTO requests
                (id,status,action,profile,reason,requested_by_uid,canonical_json,canonical_hash,
                 description,nonce,created_at,pending_until) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (request_id, "pending", canonical["action"], canonical["profile"], canonical["reason"],
                 requested_by_uid, serialized, digest, card, nonce, now, deadline))
            self._event(request_id, "request_created", now, action=canonical["action"],
                        profile=canonical["profile"], ttl_seconds=canonical["ttl_seconds"],
                        requested_by_uid=requested_by_uid, canonical_hash=digest)
        return self.get(request_id)

    def list_state(self, state: str, offset: int = 0, limit: int = 10) -> list[sqlite3.Row]:
        if state not in ("pending", "posted"):
            raise StateError("invalid list state")
        if type(offset) is not int or not 0 <= offset <= 10000:
            raise StateError("invalid list offset")
        return list(self.db.execute("SELECT * FROM requests WHERE status=? ORDER BY created_at LIMIT ? OFFSET ?",
                                    (state, limit, offset)))

    def mark_posted(self, request_id: str, message_id: str, now: float) -> sqlite3.Row:
        if not isinstance(message_id, str) or not message_id.isdecimal():
            raise StateError("invalid Discord message ID")
        with self.db:
            row = self.get(request_id)
            if row["status"] != "pending" or now >= row["pending_until"]:
                raise StateError("request is no longer pending")
            self.db.execute("UPDATE requests SET status='posted',posted_message_id=? WHERE id=?",
                            (message_id, request_id))
            self._event(request_id, "approval_posted", now, discord_message_id=message_id)
        return self.get(request_id)

    def decide(self, request_id: str, decision: str, nonce: str, canonical_hash: str,
               user_id: str, guild_id: str, channel_id: str, message_id: str, interaction_id: str,
               allowed_ids: tuple[str, str, str], now: float) -> sqlite3.Row:
        if decision not in ("approve", "deny"):
            raise StateError("invalid decision")
        if (user_id, guild_id, channel_id) != allowed_ids:
            raise StateError("Discord actor or location is not allowed")
        if not isinstance(interaction_id, str) or not interaction_id.isdecimal():
            raise StateError("invalid interaction ID")
        with self.db:
            row = self.get(request_id)
            if row["status"] != "posted" or now >= row["pending_until"]:
                raise StateError("request is not awaiting approval")
            if message_id != row["posted_message_id"]:
                raise StateError("Discord message does not match posted approval")
            actual_hash = hashlib.sha256(row["canonical_json"].encode()).hexdigest()
            if not (secrets.compare_digest(row["nonce"], nonce)
                    and secrets.compare_digest(row["canonical_hash"], canonical_hash)
                    and secrets.compare_digest(actual_hash, canonical_hash)):
                raise StateError("approval binding does not match")
            status = "approved" if decision == "approve" else "denied"
            self.db.execute("""UPDATE requests SET status=?,approved_by_discord_id=?,interaction_id=?,
                              approved_at=? WHERE id=?""", (status, user_id, interaction_id, now, request_id))
            self._event(request_id, "approval_granted" if decision == "approve" else "approval_denied", now,
                        action=row["action"], profile=row["profile"],
                        approved_by_discord_id=user_id, canonical_hash=canonical_hash)
        return self.get(request_id)

    def mark_executing(self, request_id: str, rollback: dict[str, Any], now: float) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] != "approved":
                raise StateError("request is not approved")
            self.db.execute("UPDATE requests SET status='executing',rollback_json=? WHERE id=?",
                            (canonical_json(rollback), request_id))
            self._event(request_id, "execution_started", now, action=row["action"], profile=row["profile"])
        return self.get(request_id)

    def mark_active(self, request_id: str, now: float) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] != "executing":
                raise StateError("request is not executing")
            ttl = json.loads(row["canonical_json"])["ttl_seconds"]
            self.db.execute("UPDATE requests SET status='active',active_until=? WHERE id=?",
                            (now + ttl, request_id))
            self._event(request_id, "grant_active", now, active_until=now + ttl)
        return self.get(request_id)

    def mark_failed(self, request_id: str, error: str, now: float) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] not in ("approved", "executing"):
                raise StateError("request cannot fail from this state")
            self.db.execute("UPDATE requests SET status='failed',last_error=? WHERE id=?", (error[:200], request_id))
            self._event(request_id, "execution_failed", now, error=error[:200])
        return self.get(request_id)

    def mark_rolled_back(self, request_id: str, now: float) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] != "active":
                raise StateError("request is not active")
            self.db.execute("UPDATE requests SET status='rolled_back' WHERE id=?", (request_id,))
            self._event(request_id, "grant_rolled_back", now)
        return self.get(request_id)

    def expire_pending(self, now: float) -> int:
        rows = list(self.db.execute("SELECT id FROM requests WHERE status IN ('pending','posted') AND pending_until<=?", (now,)))
        with self.db:
            for row in rows:
                self.db.execute("UPDATE requests SET status='expired' WHERE id=?", (row["id"],))
                self._event(row["id"], "approval_expired", now)
        return len(rows)

    def recovery_rows(self, now: float) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT * FROM requests WHERE status IN ('approved','executing')
              OR (status='active' AND active_until<=?) ORDER BY created_at""", (now,)))

    def rollback_error(self, request_id: str, error: str, now: float) -> None:
        with self.db:
            self.db.execute("UPDATE requests SET last_error=? WHERE id=?", (error[:200], request_id))
            self._event(request_id, "rollback_failed", now, error=error[:200])

    def public(self, row: sqlite3.Row, include_nonce: bool = False) -> dict[str, Any]:
        fields = ("id", "status", "action", "profile", "description", "canonical_hash",
                  "created_at", "pending_until", "posted_message_id", "active_until", "last_error")
        result = {field: row[field] for field in fields}
        if include_nonce:
            result["nonce"] = row["nonce"]
        return result

    def flush_audit(self) -> int:
        rows = list(self.db.execute("SELECT id,payload FROM audit_outbox WHERE flushed=0 ORDER BY rowid"))
        if not rows:
            return 0
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.audit_path, flags, 0o600)
        try:
            for row in rows:
                remaining = memoryview((row["payload"] + "\n").encode())
                while remaining:
                    written = os.write(fd, remaining)
                    if written == 0:
                        raise OSError("audit write made no progress")
                    remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        with self.db:
            self.db.executemany("UPDATE audit_outbox SET flushed=1 WHERE id=?", [(row["id"],) for row in rows])
        return len(rows)
