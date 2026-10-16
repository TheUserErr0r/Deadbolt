"""Canonical requests, transactional transitions, and durable audit outbox."""

from __future__ import annotations

import hashlib
import base64
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
import uuid
from typing import Any

from deadbolt.access import command_summary
from deadbolt.ssh_exec import MAX_OUTPUT_BYTES, redact


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class StateError(ValueError):
    pass


class Store:
    def __init__(self, path: Path, audit_path: Path, pending_ttl_seconds: int = 600,
                 restricted_ssh_audit_path: Path | None = None):
        self.audit_path = audit_path
        if restricted_ssh_audit_path == audit_path:
            raise StateError("SSH output requires a separate restricted audit path")
        self.restricted_ssh_audit_path = restricted_ssh_audit_path
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
            CREATE TABLE IF NOT EXISTS operator_audit_outbox (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, flushed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS restricted_ssh_outbox (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, flushed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS access_executions (
                id TEXT PRIMARY KEY, request_id TEXT NOT NULL, command_index INTEGER NOT NULL,
                state TEXT NOT NULL, started_at REAL NOT NULL, finished_at REAL, result_json TEXT,
                argv_json TEXT,
                FOREIGN KEY (request_id) REFERENCES requests(id),
                UNIQUE(request_id,command_index)
            );
            CREATE TABLE IF NOT EXISTS emergency_switch (
                id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL,
                generation INTEGER NOT NULL, workload_units_json TEXT NOT NULL,
                previously_active_json TEXT NOT NULL, updated_at REAL NOT NULL
            );
            INSERT OR IGNORE INTO emergency_switch
                (id,state,generation,workload_units_json,previously_active_json,updated_at)
                VALUES(1,'inactive',0,'[]','[]',0);
            CREATE INDEX IF NOT EXISTS requests_status ON requests(status);
            CREATE INDEX IF NOT EXISTS audit_unflushed ON audit_outbox(flushed);
            CREATE INDEX IF NOT EXISTS operator_audit_unflushed ON operator_audit_outbox(flushed);
        """)
        if "argv_json" not in {row[1] for row in self.db.execute("PRAGMA table_info(access_executions)")}:
            self.db.execute("ALTER TABLE access_executions ADD COLUMN argv_json TEXT")

    def close(self) -> None:
        self.db.close()

    def _event(self, request_id: str, event: str, now: float, **fields: object) -> None:
        record = {"event_id": str(uuid.uuid4()), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                  "request_id": request_id, "event": event, **fields}
        self.db.execute("INSERT INTO audit_outbox(id,request_id,payload) VALUES(?,?,?)",
                        (record["event_id"], request_id, canonical_json(record)))

    def _restricted_ssh_event(self, request_id: str, execution_id: str, event: str,
                              now: float, **fields: object) -> None:
        if self.restricted_ssh_audit_path is None:
            raise StateError("restricted SSH audit sink is not configured")
        record = {"event_id": str(uuid.uuid4()), "event": event,
                  "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                  "request_id": request_id, "execution_id": execution_id, **fields}
        self.db.execute("INSERT INTO restricted_ssh_outbox(id,payload) VALUES(?,?)",
                        (record["event_id"], canonical_json(record)))

    def operator_event(self, event: str, now: float, operator_id: str,
                       interaction_id: str, result: dict[str, Any] | None = None,
                       error: str | None = None, request_id: str | None = None,
                       helper_outcome: str | None = None) -> None:
        record = {"event_id": str(uuid.uuid4()),
                  "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                  "request_id": request_id, "event": event, "approved_by_discord_id": operator_id,
                  "interaction_id": interaction_id}
        if result is not None:
            record.update(enabled=result["enabled"], expires_at=result["expires_at"],
                          helper_outcome=result["outcome"])
        if error is not None:
            record["error"] = error[:200]
        if helper_outcome is not None:
            record["helper_outcome"] = helper_outcome
        with self.db:
            self.db.execute("INSERT INTO operator_audit_outbox(id,payload) VALUES(?,?)",
                            (record["event_id"], canonical_json(record)))

    def current_capture_request_id(self) -> str | None:
        row = self.db.execute("""SELECT id FROM requests WHERE action='proxy_body_capture'
                  AND status='active' ORDER BY approved_at DESC LIMIT 1""").fetchone()
        return row["id"] if row else None

    def emergency_state(self) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM emergency_switch WHERE id=1").fetchone()
        return {"state": row["state"], "generation": row["generation"],
                "workload_units": json.loads(row["workload_units_json"]),
                "previously_active": json.loads(row["previously_active_json"]),
                "updated_at": row["updated_at"]}

    def emergency_event(self, event: str, now: float, *, operator_id: str | None = None,
                        interaction_id: str | None = None, request_id: str | None = None,
                        error: str | None = None, state_before: str | None = None,
                        state_after: str | None = None) -> None:
        with self.db:
            self._queue_emergency_event(event, now, operator_id=operator_id,
                interaction_id=interaction_id, request_id=request_id, error=error,
                state_before=state_before, state_after=state_after)

    def _queue_emergency_event(self, event: str, now: float, *, operator_id: str | None = None,
                               interaction_id: str | None = None, request_id: str | None = None,
                               error: str | None = None, state_before: str | None = None,
                               state_after: str | None = None) -> None:
        state = self.emergency_state()
        record = {"event_id": str(uuid.uuid4()),
                  "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                  "event": event, "request_id": request_id,
                  "approved_by_discord_id": operator_id, "interaction_id": interaction_id,
                  "state_before": state_before, "state_after": state_after or state["state"],
                  "generation": state["generation"],
                  "workload_units": state["workload_units"],
                  "previously_active": state["previously_active"]}
        if error is not None:
            record["error"] = error[:200]
        self.db.execute("INSERT INTO operator_audit_outbox(id,payload) VALUES(?,?)",
                        (record["event_id"], canonical_json(record)))

    def emergency_transition(self, expected: tuple[str, ...], state: str, event: str, now: float,
                             *, operator_id: str | None = None, interaction_id: str | None = None,
                             request_id: str | None = None, workload_units: tuple[str, ...] | None = None,
                             previously_active: tuple[str, ...] | None = None,
                             next_generation: bool = False) -> dict[str, Any]:
        if state not in ("inactive", "stopping", "active", "recovering"):
            raise StateError("invalid emergency state")
        with self.db:
            before = self.emergency_state()
            if before["state"] not in expected:
                raise StateError("invalid emergency state transition")
            generation = before["generation"] + int(next_generation)
            units = list(workload_units) if workload_units is not None else before["workload_units"]
            active = list(previously_active) if previously_active is not None else before["previously_active"]
            self.db.execute("""UPDATE emergency_switch SET state=?,generation=?,
                              workload_units_json=?,previously_active_json=?,updated_at=? WHERE id=1""",
                            (state, generation, canonical_json(units), canonical_json(active), now))
            self._queue_emergency_event(event, now, operator_id=operator_id,
                interaction_id=interaction_id, request_id=request_id,
                state_before=before["state"], state_after=state)
        return self.emergency_state()

    def get(self, request_id: str) -> sqlite3.Row:
        try:
            uuid.UUID(request_id)
        except (ValueError, AttributeError) as exc:
            raise StateError("invalid request ID") from exc
        row = self.db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise StateError("unknown request")
        return row

    def create(self, canonical: dict[str, Any], description: str, requested_by_uid: int, now: float,
               requested_by_discord_id: str | None = None) -> sqlite3.Row:
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
                        requested_by_uid=requested_by_uid, requested_by_discord_id=requested_by_discord_id,
                        destination=canonical.get("destination"),
                        source=canonical.get("source"), local_ip=canonical.get("local_ip"),
                        port_start=canonical.get("port_start"), port_end=canonical.get("port_end"),
                        pinned_ips=canonical.get("pinned_ips"), ports=canonical.get("ports"),
                        protocol=canonical.get("protocol"), purpose=canonical.get("purpose"),
                        first_command=(command_summary(canonical["initial_command"])
                            if canonical.get("audit_output") == "full" else canonical.get("initial_command")),
                        max_commands=canonical.get("max_commands"),
                        audit_output=canonical.get("audit_output"),
                        operation=canonical.get("operation"), hostname=canonical.get("hostname"),
                        resulting_hosts=canonical.get("hosts"), canonical_hash=digest)
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

    def invalidate_pending(self, request_id: str, now: float, reason: str) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] not in ("pending", "posted"):
                raise StateError("request is no longer pending")
            self.db.execute("UPDATE requests SET status='failed',last_error=? WHERE id=?",
                            (reason[:200], request_id))
            self._event(request_id, "request_invalidated", now, error=reason[:200])
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
            canonical = json.loads(row["canonical_json"])
            self._event(request_id, "approval_granted" if decision == "approve" else "approval_denied", now,
                        action=row["action"], profile=row["profile"],
                        approved_by_discord_id=user_id, canonical_hash=canonical_hash,
                        destination=canonical.get("destination"),
                        source=canonical.get("source"), local_ip=canonical.get("local_ip"),
                        port_start=canonical.get("port_start"), port_end=canonical.get("port_end"),
                        protocol=canonical.get("protocol"),
                        pinned_ips=canonical.get("pinned_ips"), purpose=canonical.get("purpose"),
                        first_command=(command_summary(canonical["initial_command"])
                            if canonical.get("audit_output") == "full" else canonical.get("initial_command")),
                        max_commands=canonical.get("max_commands"),
                        operation=canonical.get("operation"), hostname=canonical.get("hostname"),
                        resulting_hosts=canonical.get("hosts"))
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

    def mark_active(self, request_id: str, now: float, *, active_until: float | None = None,
                    helper_outcome: str | None = None) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] != "executing":
                raise StateError("request is not executing")
            ttl = json.loads(row["canonical_json"])["ttl_seconds"]
            expiry = active_until if active_until is not None else now + ttl
            self.db.execute("UPDATE requests SET status='active',active_until=? WHERE id=?",
                            (expiry, request_id))
            fields = {"active_until": expiry, "approved_by_discord_id": row["approved_by_discord_id"]}
            if row["action"] == "access_grant":
                canonical = json.loads(row["canonical_json"])
                fields.update(destination=canonical["destination"], pinned_ips=canonical["pinned_ips"],
                              ports=canonical["ports"], protocol=canonical["protocol"],
                              purpose=canonical["purpose"], rule_identity=json.loads(row["rollback_json"]))
            elif row["action"] == "outbound_access":
                canonical = json.loads(row["canonical_json"])
                intent = json.loads(row["rollback_json"])
                fields.update(destination=canonical["destination"], port=canonical["port"],
                              protocol=canonical["transport"], purpose=canonical["purpose"],
                              kind=canonical["kind"], uid=intent["uid"],
                              rule_identity=intent["tag"])
            elif row["action"] == "ingress_access":
                canonical = json.loads(row["canonical_json"])
                intent = json.loads(row["rollback_json"])
                fields.update(source=canonical["source"], local_ip=canonical["local_ip"],
                              protocol=canonical["protocol"],
                              port_start=canonical["port_start"], port_end=canonical["port_end"],
                              rule_identity=intent["tag"])
            if helper_outcome is not None:
                fields["helper_outcome"] = helper_outcome
            self._event(request_id, "grant_active", now, **fields)
        return self.get(request_id)

    def mark_completed(self, request_id: str, now: float, outcome: str) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] != "executing":
                raise StateError("request is not executing")
            self.db.execute("UPDATE requests SET status='completed' WHERE id=?", (request_id,))
            canonical = json.loads(row["canonical_json"])
            self._event(request_id, "configuration_applied", now, action=row["action"],
                        approved_by_discord_id=row["approved_by_discord_id"], outcome=outcome,
                        operation=canonical.get("operation"), hostname=canonical.get("hostname"),
                        resulting_hosts=canonical.get("hosts"))
        return self.get(request_id)

    def mark_failed(self, request_id: str, error: str, now: float,
                    helper_outcome: str | None = None) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] not in ("approved", "executing"):
                raise StateError("request cannot fail from this state")
            self.db.execute("UPDATE requests SET status='failed',last_error=? WHERE id=?", (error[:200], request_id))
            fields = {"error": error[:200]}
            canonical = json.loads(row["canonical_json"])
            fields.update(action=row["action"], operation=canonical.get("operation"),
                          hostname=canonical.get("hostname"),
                          requested_hosts=canonical.get("hosts"))
            if helper_outcome is not None:
                fields["helper_outcome"] = helper_outcome
            self._event(request_id, "execution_failed", now, **fields)
        return self.get(request_id)

    def mark_rolled_back(self, request_id: str, now: float,
                         reason: str | None = None) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] != "active":
                raise StateError("request is not active")
            self.db.execute("UPDATE requests SET status='rolled_back',last_error=? WHERE id=?",
                            (reason, request_id))
            self._event(request_id, "grant_rolled_back", now, reason=reason)
        return self.get(request_id)

    def begin_access_revoke(self, request_id: str, now: float, operator_id: str) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["action"] != "access_grant" or row["status"] not in ("active", "revoking"):
                raise StateError("access grant is not active")
            if row["status"] == "active":
                intent = json.loads(row["rollback_json"])
                intent["revoke_operator_id"] = operator_id
                self.db.execute("UPDATE requests SET status='revoking',rollback_json=? WHERE id=?",
                                (canonical_json(intent), request_id))
                self._event(request_id, "grant_revoke_started", now,
                            revoked_by_discord_id=operator_id)
        return self.get(request_id)

    def begin_outbound_revoke(self, request_id: str, now: float, operator_id: str) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["action"] != "outbound_access" or row["status"] not in ("active", "revoking"):
                raise StateError("outbound grant is not active")
            if row["status"] == "active":
                self.db.execute("UPDATE requests SET status='revoking' WHERE id=?", (request_id,))
                self._event(request_id, "outbound_revoke_started", now,
                            revoked_by_discord_id=operator_id)
        return self.get(request_id)

    def mark_outbound_revoked(self, request_id: str, now: float, operator_id: str,
                              reason: str = "operator") -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["action"] != "outbound_access" or row["status"] != "revoking":
                raise StateError("outbound grant is not revoking")
            self.db.execute("UPDATE requests SET status='revoked',last_error=? WHERE id=?",
                            (reason, request_id))
            self._event(request_id, "outbound_revoked", now,
                        revoked_by_discord_id=operator_id, reason=reason)
        return self.get(request_id)

    def active_outbound_rows(self) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT * FROM requests WHERE action='outbound_access'
                                    AND status IN ('active','revoking') ORDER BY created_at"""))

    def active_ingress_rows(self) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT * FROM requests WHERE action='ingress_access'
                                    AND status IN ('active','executing','revoking') ORDER BY created_at"""))

    def begin_ingress_revoke(self, request_id: str, now: float, requester_uid: int,
                             *, replacement_id: str | None = None) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if (row["action"] != "ingress_access" or row["requested_by_uid"] != requester_uid
                    or row["status"] not in ("active", "executing", "revoking")):
                raise StateError("ingress grant is not active or owned by requester")
            if row["status"] in ("active", "executing"):
                self.db.execute("UPDATE requests SET status='revoking' WHERE id=?", (request_id,))
                self._event(request_id, "ingress_revoke_started", now,
                            revoked_by_uid=requester_uid, replacement_request_id=replacement_id)
        return self.get(request_id)

    def mark_ingress_revoked(self, request_id: str, now: float, requester_uid: int,
                             reason: str, *, replacement_id: str | None = None) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["action"] != "ingress_access" or row["status"] != "revoking":
                raise StateError("ingress grant is not revoking")
            expired = reason == "expired"
            self.db.execute("UPDATE requests SET status=?,last_error=? WHERE id=?",
                            ("expired" if expired else "revoked", reason[:200], request_id))
            self._event(request_id, "ingress_expired" if expired else "ingress_revoked", now,
                        revoked_by_uid=requester_uid, reason=reason,
                        replacement_request_id=replacement_id)
        return self.get(request_id)

    def mark_revoked(self, request_id: str, now: float, operator_id: str) -> sqlite3.Row:
        with self.db:
            row = self.get(request_id)
            if row["status"] != "revoking" or row["action"] != "access_grant":
                raise StateError("access grant is not revoking")
            self.db.execute("UPDATE requests SET status='revoked' WHERE id=?", (request_id,))
            self._event(request_id, "grant_revoked", now,
                        approved_by_discord_id=row["approved_by_discord_id"],
                        revoked_by_discord_id=operator_id)
        return self.get(request_id)

    def begin_access_execution(self, request_id: str, command: list[str], now: float) -> tuple[sqlite3.Row, str, int]:
        with self.db:
            row = self.get(request_id)
            if (row["action"] != "access_grant" or row["status"] != "active"
                    or row["active_until"] <= now):
                raise StateError("approved SSH grant is absent or expired")
            canonical = json.loads(row["canonical_json"])
            if not canonical["audited_execution"] or not canonical["initial_command"]:
                raise StateError("grant does not permit SSH execution")
            count = self.db.execute("SELECT COUNT(*) FROM access_executions WHERE request_id=?",
                                    (request_id,)).fetchone()[0]
            if count >= canonical["max_commands"]:
                raise StateError("approved SSH session command limit reached")
            if count == 0 and command != canonical["initial_command"]:
                raise StateError("first SSH command differs from approved argv")
            running = self.db.execute("""SELECT 1 FROM access_executions
                        WHERE request_id=? AND state='started'""", (request_id,)).fetchone()
            if running:
                raise StateError("another SSH command is in progress")
            index = count + 1
            execution_id = str(uuid.uuid4())
            self.db.execute("""INSERT INTO access_executions
                (id,request_id,command_index,state,started_at,argv_json) VALUES(?,?,?,?,?,?)""",
                (execution_id, request_id, index, "started", now,
                 canonical_json(command) if canonical["audit_output"] == "full" else None))
            if canonical["audit_output"] == "full":
                self._restricted_ssh_event(request_id, execution_id, "ssh_execution_started", now,
                    approval_id=row["interaction_id"], command_index=index,
                    destination=canonical["destination"], pinned_ip=canonical["pinned_ips"][0],
                    ssh_user=canonical["ssh_user"], argv=command, started_at=now)
            self._event(request_id, "ssh_execution_started", now,
                        approved_by_discord_id=row["approved_by_discord_id"],
                        destination=canonical["destination"], pinned_ips=canonical["pinned_ips"],
                        ssh_user=canonical["ssh_user"], command_index=index,
                        command=(command_summary(command) if canonical["audit_output"] == "full"
                                 else [redact(part) for part in command]))
        return row, execution_id, index

    def finish_access_execution(self, execution_id: str, now: float, result: dict[str, Any]) -> None:
        with self.db:
            row = self.db.execute("SELECT request_id,state FROM access_executions WHERE id=?", (execution_id,)).fetchone()
            if row is None or row["state"] != "started":
                raise StateError("SSH execution is not in progress")
            request = self.get(row["request_id"])
            canonical = json.loads(request["canonical_json"])
            if canonical["audit_output"] == "full":
                self._restricted_ssh_event(row["request_id"], execution_id,
                    "ssh_execution_completed", now, approval_id=request["interaction_id"],
                    command_index=result["command_index"],
                    destination=result["destination"], pinned_ip=result["pinned_ip"],
                    ssh_user=result["ssh_user"], argv=result["command"],
                    started_at=result["started_at"], finished_at=result["finished_at"],
                    exit_code=result["exit_code"], termination=result["termination"],
                    timed_out=result["timed_out"], stdout_b64=result["stdout_b64"],
                    stderr_b64=result["stderr_b64"],
                    stdout_truncated=result["stdout_truncated"],
                    stderr_truncated=result["stderr_truncated"],
                    output_encoding="base64")
                self.db.execute("""UPDATE access_executions SET state='evidence_pending',
                                   finished_at=?,result_json=? WHERE id=?""",
                                (now, canonical_json({**{key: value for key, value in result.items()
                                    if key not in ("command", "stdout_b64", "stderr_b64")},
                                    "command_summary": command_summary(result["command"])}),
                                 execution_id))
                return
            self.db.execute("""UPDATE access_executions SET state='finished',finished_at=?,result_json=?
                               WHERE id=?""", (now, canonical_json(result), execution_id))
            self._event(row["request_id"], "ssh_execution_finished", now,
                        **{key: value for key, value in result.items()
                           if key not in ("request_id", "stdout", "stderr", "stdout_b64", "stderr_b64")})

    def finalize_access_execution(self, execution_id: str, now: float) -> None:
        with self.db:
            row = self.db.execute("SELECT request_id,state,result_json FROM access_executions WHERE id=?",
                                  (execution_id,)).fetchone()
            if row is None or row["state"] != "evidence_pending":
                raise StateError("SSH evidence is not awaiting delivery")
            result = json.loads(row["result_json"])
            self.db.execute("UPDATE access_executions SET state='finished' WHERE id=?", (execution_id,))
            self._event(row["request_id"], "ssh_execution_finished", now,
                approved_by_discord_id=self.get(row["request_id"])["approved_by_discord_id"],
                command_index=result["command_index"], destination=result["destination"],
                pinned_ip=result["pinned_ip"], ssh_user=result["ssh_user"],
                command=result["command_summary"], exit_code=result["exit_code"],
                started_at=result["started_at"], finished_at=result["finished_at"],
                termination=result["termination"], timed_out=result["timed_out"],
                stdout_truncated=result["stdout_truncated"],
                stderr_truncated=result["stderr_truncated"], audit_output="full")

    def fail_access_execution(self, execution_id: str, now: float, error: str) -> None:
        with self.db:
            row = self.db.execute("SELECT request_id,state FROM access_executions WHERE id=?", (execution_id,)).fetchone()
            if row is None or row["state"] not in ("started", "evidence_pending"):
                raise StateError("SSH execution is not in progress")
            self.db.execute("UPDATE access_executions SET state='failed',finished_at=? WHERE id=?",
                            (now, execution_id))
            self._event(row["request_id"], "ssh_execution_failed", now, error=error[:200])

    def interrupt_access_execution(self, execution_id: str, now: float,
                                   partial: dict[str, Any] | None,
                                   reason: str = "emergency_stop") -> bool:
        """Durably queue a full-evidence interruption before marking a command failed."""
        if reason not in ("emergency_stop", "executor_restart"):
            raise StateError("invalid SSH interruption reason")
        partial = partial or {}
        with self.db:
            row = self.db.execute("SELECT * FROM access_executions WHERE id=?",
                                  (execution_id,)).fetchone()
            if row is None or row["state"] != "started":
                return False
            request = self.get(row["request_id"])
            canonical = json.loads(request["canonical_json"])
            if canonical["audit_output"] != "full":
                self.fail_access_execution(execution_id, now, f"interrupted by {reason}")
                return True
            encoded = {}
            for stream in ("stdout", "stderr"):
                value = partial.get(stream + "_b64", "")
                if not isinstance(value, str):
                    raise StateError("invalid interrupted SSH output")
                try:
                    data = base64.b64decode(value, validate=True)
                except (ValueError, base64.binascii.Error) as exc:
                    raise StateError("invalid interrupted SSH output") from exc
                if len(data) > MAX_OUTPUT_BYTES:
                    raise StateError("interrupted SSH output exceeds policy")
                encoded[stream + "_b64"] = value
                flag = partial.get(stream + "_truncated", False)
                if type(flag) is not bool:
                    raise StateError("invalid interrupted SSH truncation state")
                encoded[stream + "_truncated"] = flag
            if row["argv_json"] is None:
                raise StateError("SSH execution argv is unavailable for interruption evidence")
            self._restricted_ssh_event(row["request_id"], execution_id,
                "ssh_execution_interrupted", now, approval_id=request["interaction_id"],
                command_index=row["command_index"], destination=canonical["destination"],
                pinned_ip=canonical["pinned_ips"][0], ssh_user=canonical["ssh_user"],
                argv=json.loads(row["argv_json"]), started_at=row["started_at"],
                finished_at=now, reason=reason, output_incomplete=True,
                output_encoding="base64", **encoded)
            self.db.execute("UPDATE access_executions SET state='failed',finished_at=? WHERE id=?",
                            (now, execution_id))
            self._event(row["request_id"], "ssh_execution_failed", now,
                        error=f"interrupted by {reason}", command_index=row["command_index"])
        return True

    def interrupted_access_executions(self) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT id,request_id,command_index FROM access_executions
                                     WHERE state IN ('started','evidence_pending')"""))

    def access_execution_state(self, execution_id: str) -> str:
        row = self.db.execute("SELECT state FROM access_executions WHERE id=?", (execution_id,)).fetchone()
        if row is None:
            raise StateError("SSH execution is missing")
        return row["state"]

    def access_revoke_rows(self) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT * FROM requests WHERE action='access_grant'
                                     AND status IN ('active','revoking') ORDER BY created_at"""))

    def active_access_rows(self) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT * FROM requests WHERE action='access_grant'
                                     AND status='active' ORDER BY created_at"""))

    def failed_access_rows(self) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT r.* FROM requests r WHERE r.action='access_grant'
            AND r.status='active' AND EXISTS (SELECT 1 FROM access_executions e
                WHERE e.request_id=r.id AND e.state='failed') ORDER BY r.created_at"""))

    def expire_pending(self, now: float) -> int:
        rows = list(self.db.execute("SELECT id FROM requests WHERE status IN ('pending','posted') AND pending_until<=?", (now,)))
        with self.db:
            for row in rows:
                self.db.execute("UPDATE requests SET status='expired' WHERE id=?", (row["id"],))
                self._event(row["id"], "approval_expired", now)
        return len(rows)

    def recovery_rows(self, now: float) -> list[sqlite3.Row]:
        return list(self.db.execute("""SELECT * FROM requests WHERE status IN ('approved','executing','revoking')
              OR (status='active' AND action IN ('firewall_profile','access_grant','outbound_access','ingress_access') AND active_until<=?) ORDER BY created_at""", (now,)))

    def close_capture_grants(self, now: float, event: str, *, except_id: str | None = None) -> None:
        if event not in ("capture_superseded", "capture_observed_disabled"):
            raise StateError("invalid capture closure event")
        next_status = "superseded" if event == "capture_superseded" else "closed"
        with self.db:
            rows = self.db.execute("""SELECT id FROM requests WHERE action='proxy_body_capture'
                      AND status='active' AND id<>?""", (except_id or "",)).fetchall()
            for row in rows:
                self.db.execute("UPDATE requests SET status=? WHERE id=?", (next_status, row["id"]))
                self._event(row["id"], event, now)

    def rollback_error(self, request_id: str, error: str, now: float) -> None:
        with self.db:
            self.db.execute("UPDATE requests SET last_error=? WHERE id=?", (error[:200], request_id))
            self._event(request_id, "rollback_failed", now, error=error[:200])

    def public(self, row: sqlite3.Row, include_nonce: bool = False) -> dict[str, Any]:
        fields = ("id", "status", "action", "profile", "description", "canonical_hash",
                  "created_at", "pending_until", "posted_message_id", "active_until", "last_error")
        result = {field: row[field] for field in fields}
        if row["action"] == "outbound_access" and row["rollback_json"] and row["status"] == "active":
            intent = json.loads(row["rollback_json"])
            if intent.get("kind") == "ssh":
                result["proxy_host"] = "127.0.0.1"
                result["proxy_port"] = intent.get("proxy_port")
        if row["action"] == "outbound_access":
            canonical = json.loads(row["canonical_json"])
            result["raw_ssh_bypass"] = (canonical["kind"] == "raw"
                                        and canonical["transport"] == "tcp"
                                        and canonical["port"] == 22)
        if row["action"] == "ingress_access":
            canonical = json.loads(row["canonical_json"])
            result.update(source=canonical["source"], local_ip=canonical["local_ip"],
                          protocol=canonical["protocol"],
                          port_start=canonical["port_start"], port_end=canonical["port_end"])
        if include_nonce:
            result["nonce"] = row["nonce"]
        return result

    def flush_audit(self) -> int:
        rows = list(self.db.execute("""SELECT rowid AS seq,id,payload,'request' AS kind FROM audit_outbox WHERE flushed=0
              UNION ALL SELECT rowid AS seq,id,payload,'operator' AS kind FROM operator_audit_outbox WHERE flushed=0
              ORDER BY kind DESC,seq"""))
        restricted_count = self.flush_restricted_audit()
        if not rows:
            return restricted_count
        self._append_records(self.audit_path, rows)
        with self.db:
            self.db.executemany("UPDATE audit_outbox SET flushed=1 WHERE id=?",
                                [(row["id"],) for row in rows if row["kind"] == "request"])
            self.db.executemany("UPDATE operator_audit_outbox SET flushed=1 WHERE id=?",
                                [(row["id"],) for row in rows if row["kind"] == "operator"])
        return len(rows) + restricted_count

    @staticmethod
    def _append_records(path: Path, records: list[sqlite3.Row]) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            for item in records:
                remaining = memoryview((item["payload"] + "\n").encode())
                while remaining:
                    written = os.write(fd, remaining)
                    if written == 0:
                        raise OSError("audit write made no progress")
                    remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def check_restricted_sink(self) -> None:
        if self.restricted_ssh_audit_path is None:
            raise StateError("restricted SSH audit sink is not configured")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.restricted_ssh_audit_path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077):
                raise StateError("restricted SSH audit sink is not private")
            os.fsync(fd)
        finally:
            os.close(fd)

    def flush_restricted_audit(self) -> int:
        restricted = list(self.db.execute("SELECT id,payload FROM restricted_ssh_outbox WHERE flushed=0"))
        if not restricted:
            return 0
        self.check_restricted_sink()
        assert self.restricted_ssh_audit_path is not None
        self._append_records(self.restricted_ssh_audit_path, restricted)
        with self.db:
            self.db.executemany("UPDATE restricted_ssh_outbox SET flushed=1 WHERE id=?",
                                [(row["id"],) for row in restricted])
        return len(restricted)
