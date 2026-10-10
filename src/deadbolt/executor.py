"""Root executor: the only component permitted to change host policy."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import pwd
import socket
import stat
import time
from datetime import datetime, timezone
from typing import Any, Callable

from deadbolt.actions import ActionError, CaptureAction, CaptureError, EmergencyAction, ExclusionsAction, UfwAction
from deadbolt.config import ConfigurationError, ExecutorConfig, Policy, describe_action, normalize_workload_units, resolve_action
from deadbolt.protocol import MAX_MESSAGE_BYTES, ProtocolError, peer_uid, read_message, require_fields, write_message
from deadbolt.store import StateError, Store, canonical_json

LOG = logging.getLogger(__name__)


class Executor:
    def __init__(self, config: ExecutorConfig, policy: Policy, store: Store,
                 action: UfwAction | None = None, clock: Callable[[], float] = time.time,
                 policy_loader: Callable[[], Policy] | None = None,
                 capture_action: CaptureAction | None = None,
                 exclusions_action: ExclusionsAction | None = None,
                 emergency_action: EmergencyAction | None = None):
        self.config = config
        self.policy = policy
        self.policy_loader = policy_loader or (lambda: Policy.load(config.profiles_path))
        self.store = store
        self.action = action or UfwAction()
        self.capture_action = capture_action or CaptureAction()
        self.exclusions_action = exclusions_action or ExclusionsAction()
        self.clock = clock
        self.lock = asyncio.Lock()
        bot_account = pwd.getpwnam(config.bot_user)
        self.bot_uid = bot_account.pw_uid
        self.bot_gid = bot_account.pw_gid
        self.hermes_uid = pwd.getpwnam(config.hermes_user).pw_uid
        self.emergency_action = emergency_action or EmergencyAction(self.hermes_uid)

    def _revalidate(self, row: Any) -> dict[str, Any]:
        original = json.loads(row["canonical_json"])
        capture = original["action"] == "proxy_body_capture"
        exclusions = original["action"] == "body_capture_exclusions"
        policy = self.policy_loader()
        if original["action"] == "emergency_recover":
            state = self.store.emergency_state()
            current = self._recovery_canonical(state, policy)
        elif exclusions:
            self.exclusions_action.validate(original)
            if (original["hostname"] not in policy.body_exclusion_allowed_hosts
                    or not set(original["hosts"]).issubset(policy.body_exclusion_allowed_hosts)):
                raise StateError("exclusions no longer match root policy")
            current = original
        else:
            current = resolve_action(original["action"], original["profile"], original["reason"],
                                     None if capture else original["ttl_seconds"],
                                     policy, self.config,
                                     original.get("hours") if capture else None)
        if (canonical_json(current) != row["canonical_json"] or
                hashlib.sha256(row["canonical_json"].encode()).hexdigest() != row["canonical_hash"]):
            raise StateError("stored action no longer matches root policy")
        if original["action"] != "emergency_recover":
            (self.capture_action if capture else self.exclusions_action if exclusions else self.action).validate(current)
        return current

    @staticmethod
    def _recovery_canonical(state: dict[str, Any], policy: Policy) -> dict[str, Any]:
        if state["state"] != "active" or tuple(state["workload_units"]) != policy.emergency_workload_units:
            raise StateError("emergency state or root policy changed before recovery")
        normalize_workload_units(state["workload_units"])
        if not set(state["previously_active"]).issubset(
                {EmergencyAction.proxy_unit, *state["workload_units"]}):
            raise StateError("invalid saved emergency service state")
        return {"action": "emergency_recover", "profile": "emergency_recover",
                "operation": "recover", "generation": state["generation"],
                "workload_units": state["workload_units"],
                "previously_active": state["previously_active"],
                "ttl_seconds": 0, "reason": "operator emergency recovery"}

    async def dispatch(self, message: dict[str, Any], uid: int) -> dict[str, Any]:
        if uid != self.bot_uid:
            raise ProtocolError("unauthorized Unix peer")
        async with self.lock:
            try:
                result = await self._dispatch_locked(message)
            finally:
                try:
                    self.store.flush_audit()
                except OSError:
                    LOG.exception("audit JSONL flush failed; durable outbox will retry")
            return result

    async def _dispatch_locked(self, message: dict[str, Any]) -> dict[str, Any]:
        op = message.get("op")
        now = self.clock()
        if op == "create":
            require_fields(message, {"op", "action", "profile", "reason", "requested_by_uid"},
                           {"ttl_seconds", "hours"})
            if type(message["requested_by_uid"]) is not int or message["requested_by_uid"] != self.hermes_uid:
                raise ProtocolError("invalid claimed request origin")
            if not all(isinstance(message[key], str) for key in ("action", "profile", "reason")):
                raise ProtocolError("invalid request fields")
            canonical = resolve_action(message["action"], message["profile"], message["reason"],
                                       message.get("ttl_seconds"), self.policy_loader(), self.config,
                                       message.get("hours"))
            action = (self.capture_action if canonical["action"] == "proxy_body_capture" else
                      self.action)
            action.validate(canonical)
            row = self.store.create(canonical, action.describe(canonical), self.hermes_uid, now)
            return {"ok": True, "request": self.store.public(row)}
        if op == "exclusion_create":
            require_fields(message, {"op", "operation", "hostname", "user_id", "guild_id",
                                     "channel_id", "interaction_id"})
            self._operator(message)
            if not isinstance(message["operation"], str) or not isinstance(message["hostname"], str):
                raise ProtocolError("invalid exclusion fields")
            try:
                canonical = self.exclusions_action.create_change(
                    message["operation"], message["hostname"],
                    self.policy_loader().body_exclusion_allowed_hosts)
            except (ActionError, ConfigurationError) as exc:
                self.store.operator_event("exclusion_request_failed", now, message["user_id"],
                                          message["interaction_id"], error=str(exc))
                raise
            row = self.store.create(canonical, self.exclusions_action.describe(canonical),
                                    self.bot_uid, now, requested_by_discord_id=message["user_id"])
            return {"ok": True, "request": self.store.public(row)}
        if op in ("emergency_status", "emergency_stop", "emergency_recover_create"):
            require_fields(message, {"op", "user_id", "guild_id", "channel_id", "interaction_id"})
            self._operator(message)
            if op == "emergency_status":
                try:
                    enforced = self.emergency_action.enabled()
                    state = self.store.emergency_state()
                    running = self.emergency_action.active_units(tuple(state["workload_units"]))
                except ActionError as exc:
                    self.store.emergency_event("emergency_status_failed", now,
                        operator_id=message["user_id"], interaction_id=message["interaction_id"],
                        error=str(exc))
                    raise
                self.store.emergency_event("emergency_status", now,
                    operator_id=message["user_id"], interaction_id=message["interaction_id"])
                return {"ok": True, "emergency": {**state, "egress_block_enforced": enforced,
                                                     "running_units": list(running)}}
            if op == "emergency_stop":
                state = self.store.emergency_state()
                if state["state"] == "inactive":
                    units = self.policy_loader().emergency_workload_units
                    try:
                        previous = self.emergency_action.active_units(units)
                    except ActionError as exc:
                        self.store.emergency_event("emergency_stop_failed", now,
                            operator_id=message["user_id"], interaction_id=message["interaction_id"],
                            error=str(exc))
                        raise
                    state = self.store.emergency_transition(("inactive",), "stopping",
                        "emergency_stop_started", now, operator_id=message["user_id"],
                        interaction_id=message["interaction_id"], workload_units=units,
                        previously_active=previous, next_generation=True)
                try:
                    self.emergency_action.enforce(tuple(state["workload_units"]))
                except ActionError as exc:
                    self.store.emergency_event("emergency_stop_failed", self.clock(),
                        operator_id=message["user_id"], interaction_id=message["interaction_id"],
                        error=str(exc))
                    raise
                if state["state"] != "active":
                    state = self.store.emergency_transition(("stopping", "recovering"), "active",
                        "emergency_stop_active", self.clock(), operator_id=message["user_id"],
                        interaction_id=message["interaction_id"])
                else:
                    self.store.emergency_event("emergency_stop_idempotent", self.clock(),
                        operator_id=message["user_id"], interaction_id=message["interaction_id"])
                return {"ok": True, "emergency": {**state, "egress_block_enforced": True,
                                                     "running_units": []}}
            state = self.store.emergency_state()
            try:
                canonical = self._recovery_canonical(state, self.policy_loader())
            except (StateError, ConfigurationError) as exc:
                self.store.emergency_event("emergency_recovery_request_failed", now,
                    operator_id=message["user_id"], interaction_id=message["interaction_id"],
                    error=str(exc))
                raise
            row = self.store.create(canonical, describe_action(canonical), self.bot_uid, now,
                                    requested_by_discord_id=message["user_id"])
            return {"ok": True, "request": self.store.public(row)}
        if op == "list":
            require_fields(message, {"op", "state"}, {"offset"})
            offset = message.get("offset", 0)
            rows = self.store.list_state(message["state"], offset, 10)
            return {"ok": True, "requests": [self.store.public(row, include_nonce=True) for row in rows]}
        if op == "posted":
            require_fields(message, {"op", "request_id", "message_id"})
            row = self.store.mark_posted(message["request_id"], message["message_id"], now)
            return {"ok": True, "request": self.store.public(row)}
        if op == "status":
            require_fields(message, {"op", "request_id"})
            row = self.store.get(message["request_id"])
            return {"ok": True, "request": self.store.public(row)}
        if op == "decide":
            required = {"op", "request_id", "decision", "nonce", "canonical_hash", "user_id",
                        "guild_id", "channel_id", "message_id", "interaction_id"}
            require_fields(message, required)
            if any(not isinstance(message[key], str) for key in required - {"op"}):
                raise ProtocolError("invalid decision fields")
            row = self.store.get(message["request_id"])
            self._revalidate(row)
            row = self.store.decide(message["request_id"], message["decision"], message["nonce"],
                                    message["canonical_hash"], message["user_id"], message["guild_id"],
                                    message["channel_id"], message["message_id"], message["interaction_id"],
                                    (self.config.discord_user_id, self.config.discord_guild_id,
                                     self.config.discord_channel_id), now)
            if row["status"] == "approved":
                row = await self._execute(row)
            return {"ok": True, "request": self.store.public(row)}
        if op in ("capture_status", "capture_disable"):
            require_fields(message, {"op", "user_id", "guild_id", "channel_id", "interaction_id"})
            self._operator(message)
            capture_request_id = self.store.current_capture_request_id()
            try:
                result = (self.capture_action.status() if op == "capture_status"
                          else self.capture_action.disable())
            except ActionError as exc:
                self.store.operator_event(op + "_failed", now, message["user_id"],
                                          message["interaction_id"], error=str(exc),
                                          request_id=capture_request_id,
                                          helper_outcome=exc.outcome if isinstance(exc, CaptureError) else None)
                raise
            self.store.operator_event(op, self.clock(), message["user_id"],
                                      message["interaction_id"], result=result,
                                      request_id=capture_request_id)
            if not result["enabled"]:
                self.store.close_capture_grants(self.clock(), "capture_observed_disabled")
            return {"ok": True, "capture": result}
        raise ProtocolError("unknown operation")

    def _operator(self, message: dict[str, Any]) -> None:
        if any(not isinstance(message[key], str) for key in
               ("user_id", "guild_id", "channel_id", "interaction_id")):
            raise ProtocolError("invalid operator fields")
        if (message["user_id"], message["guild_id"], message["channel_id"]) != (
                self.config.discord_user_id, self.config.discord_guild_id,
                self.config.discord_channel_id):
            raise ProtocolError("Discord actor or location is not allowed")
        if not message["interaction_id"].isdecimal():
            raise ProtocolError("invalid interaction ID")

    async def _execute(self, row: Any) -> Any:
        request_id = row["id"]
        now = self.clock()
        if row["action"] == "emergency_recover":
            started = False
            try:
                canonical = self._revalidate(row)
                self.store.mark_executing(request_id, {"generation": canonical["generation"]}, now)
                started = True
                self.store.emergency_transition(("active",), "recovering",
                    "emergency_recovery_started", now,
                    operator_id=row["approved_by_discord_id"], request_id=request_id)
                self.emergency_action.recover(tuple(canonical["previously_active"]),
                                              tuple(canonical["workload_units"]))
                self.store.emergency_transition(("recovering",), "inactive",
                    "emergency_recovered", self.clock(),
                    operator_id=row["approved_by_discord_id"], request_id=request_id,
                    workload_units=(), previously_active=())
                return self.store.mark_completed(request_id, self.clock(), "recovered")
            except Exception as exc:
                if not isinstance(exc, (ActionError, ConfigurationError, StateError, OSError)):
                    LOG.exception("unexpected emergency recovery failure")
                failure = (str(exc) if isinstance(exc, (ActionError, ConfigurationError, StateError, OSError))
                           else "internal emergency recovery error")
                rollback_error = None
                if started:
                    try:
                        self.emergency_action.enforce(tuple(json.loads(row["canonical_json"])["workload_units"]))
                    except Exception as rollback_exc:
                        rollback_error = str(rollback_exc) if isinstance(rollback_exc, ActionError) else "internal emergency reblock error"
                self.store.emergency_event("emergency_recovery_failed", self.clock(),
                    operator_id=row["approved_by_discord_id"], request_id=request_id,
                    error=failure)
                if rollback_error is not None:
                    self.store.rollback_error(request_id, rollback_error, self.clock())
                    return self.store.get(request_id)
                if started:
                    state = self.store.emergency_state()
                    if state["state"] in ("recovering", "inactive"):
                        canonical = json.loads(row["canonical_json"])
                        self.store.emergency_transition((state["state"],), "active",
                            "emergency_recovery_rolled_back", self.clock(), request_id=request_id,
                            workload_units=tuple(canonical["workload_units"]),
                            previously_active=tuple(canonical["previously_active"]))
                return self.store.mark_failed(request_id, failure, self.clock())
        if row["action"] == "proxy_body_capture":
            try:
                canonical = self._revalidate(row)
                self.store.mark_executing(request_id, {"external_expiry": True}, now)
                started = self.clock()
                result = self.capture_action.enable(canonical)
                finished = self.clock()
                expiry = datetime.strptime(result["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc).timestamp()
                if not started + canonical["ttl_seconds"] - 1 <= expiry <= finished + canonical["ttl_seconds"] + 1:
                    raise ActionError("capture helper returned unexpected expiry")
                active = self.store.mark_active(request_id, self.clock(), active_until=expiry,
                                                helper_outcome=result["outcome"])
                self.store.close_capture_grants(self.clock(), "capture_superseded", except_id=request_id)
                return active
            except (ActionError, ConfigurationError, StateError, OSError) as exc:
                return self.store.mark_failed(request_id, str(exc), self.clock(),
                    helper_outcome=exc.outcome if isinstance(exc, CaptureError) else None)
        if row["action"] == "body_capture_exclusions":
            try:
                canonical = self._revalidate(row)
                intent = self.exclusions_action.prepare(canonical)
                self.store.mark_executing(request_id, intent, now)
                self.exclusions_action.apply(canonical, intent)
                return self.store.mark_completed(request_id, self.clock(), "replaced")
            except (ActionError, ConfigurationError, StateError, OSError) as exc:
                if self.store.get(request_id)["status"] == "executing":
                    try:
                        current = self.exclusions_action._read()
                        intent = json.loads(self.store.get(request_id)["rollback_json"])
                        if current == intent["after"]:
                            return self.store.mark_completed(request_id, self.clock(), "recovered_applied")
                        if hashlib.sha256(current.encode()).hexdigest() != intent["before_sha256"]:
                            self.store.rollback_error(request_id, "exclusions changed externally", self.clock())
                            return self.store.get(request_id)
                    except (ActionError, OSError):
                        self.store.rollback_error(request_id, "exclusions state needs inspection", self.clock())
                        return self.store.get(request_id)
                return self.store.mark_failed(request_id, str(exc), self.clock())
        try:
            canonical = self._revalidate(row)
            rollback = self.action.prepare(canonical, request_id)
        except (ActionError, ConfigurationError, StateError, OSError) as exc:
            return self.store.mark_failed(request_id, str(exc), now)
        row = self.store.mark_executing(request_id, rollback, now)
        try:
            self.action.apply(canonical, rollback)
            return self.store.mark_active(request_id, self.clock())
        except Exception as exc:
            LOG.exception("action apply failed for %s", request_id)
            try:
                self.action.rollback(canonical, rollback)
            except Exception as rollback_exc:
                self.store.rollback_error(request_id, str(rollback_exc), self.clock())
                return self.store.get(request_id)  # Keep executing for reconciliation.
            return self.store.mark_failed(request_id, str(exc), self.clock())

    async def reconcile(self) -> None:
        """Run before accepting connections and periodically thereafter."""
        async with self.lock:
            now = self.clock()
            self.store.expire_pending(now)
            emergency = self.store.emergency_state()
            emergency_restored = emergency["state"] == "inactive"
            if emergency["state"] != "inactive":
                try:
                    self.emergency_action.enforce(tuple(emergency["workload_units"]))
                    emergency_restored = True
                    if emergency["state"] != "active":
                        self.store.emergency_transition((emergency["state"],), "active",
                            "emergency_reconciled_to_stopped", self.clock())
                except (ActionError, ConfigurationError, StateError) as exc:
                    self.store.emergency_event("emergency_reconcile_failed", self.clock(),
                        error=str(exc))
                    LOG.exception("emergency switch reconciliation failed")
            for row in self.store.recovery_rows(now):
                if row["status"] == "approved":
                    self.store.mark_failed(row["id"], "executor stopped before apply", self.clock())
                    continue
                if row["action"] == "proxy_body_capture":
                    self.store.mark_failed(row["id"], "capture execution interrupted; inspect helper status",
                                           self.clock())
                    continue
                if row["action"] == "emergency_recover":
                    if emergency_restored and self.store.emergency_state()["state"] == "active":
                        self.store.mark_failed(row["id"],
                            "recovery interrupted; emergency stop remains active", self.clock())
                    else:
                        self.store.rollback_error(row["id"],
                            "recovery interrupted; emergency state needs inspection", self.clock())
                    continue
                if row["action"] == "body_capture_exclusions":
                    try:
                        canonical = json.loads(row["canonical_json"])
                        if hashlib.sha256(row["canonical_json"].encode()).hexdigest() != row["canonical_hash"]:
                            raise StateError("stored exclusions approval hash changed")
                        self.exclusions_action.validate(canonical)
                        intent = json.loads(row["rollback_json"])
                        expected = (self.exclusions_action.header +
                                    "".join(f"{host}\n" for host in canonical["hosts"]))
                        if intent["after"] != expected:
                            raise StateError("stored exclusions intent changed")
                        current = self.exclusions_action._read()
                        if current == intent["after"]:
                            self.store.mark_completed(row["id"], self.clock(), "recovered_applied")
                        elif hashlib.sha256(current.encode()).hexdigest() == intent["before_sha256"]:
                            self.store.mark_failed(row["id"], "exclusions write interrupted", self.clock())
                        else:
                            self.store.rollback_error(row["id"], "exclusions changed externally", self.clock())
                    except Exception:
                        LOG.exception("exclusions reconciliation failed for %s", row["id"])
                    continue
                try:
                    canonical = json.loads(row["canonical_json"])
                    rollback = json.loads(row["rollback_json"])
                    self.action.rollback(canonical, rollback)
                except Exception as exc:
                    LOG.exception("rollback failed for %s", row["id"])
                    self.store.rollback_error(row["id"], str(exc), self.clock())
                    continue
                if row["status"] == "active":
                    self.store.mark_rolled_back(row["id"], self.clock())
                else:
                    self.store.mark_failed(row["id"], "interrupted execution rolled back", self.clock())
            try:
                self.store.flush_audit()
            except OSError:
                LOG.exception("audit JSONL flush failed; durable outbox will retry")

    async def connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            sock = writer.get_extra_info("socket")
            if sock is None or peer_uid(sock) != self.bot_uid:
                raise ProtocolError("unauthorized Unix peer")
            message = await read_message(reader)
            response = await self.dispatch(message, self.bot_uid)
        except (ProtocolError, StateError, ConfigurationError, ActionError, ValueError) as exc:
            response = {"ok": False, "error": str(exc)}
        except Exception:
            LOG.exception("unexpected executor error")
            response = {"ok": False, "error": "internal error"}
        try:
            await write_message(writer, response)
        except (OSError, ProtocolError):
            pass
        writer.close()
        await writer.wait_closed()


def _secure_root_path(path: Path, directory: bool = False) -> None:
    target = path if directory else path.parent
    info = target.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f"unsafe root-owned directory: {target}")
    if not directory and path.is_symlink():
        raise RuntimeError(f"unsafe symlink: {path}")
    if path.exists() and not directory:
        own = path.lstat()
        if stat.S_ISLNK(own.st_mode) or own.st_uid != 0 or own.st_mode & 0o077:
            raise RuntimeError(f"unsafe root-owned file: {path}")


async def serve(config: ExecutorConfig, policy: Policy) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("executor must run as root")
    os.umask(0o077)
    for path in (config.state_path, config.audit_path, config.profiles_path):
        _secure_root_path(path)
    _secure_root_path(config.bot_socket.parent, directory=True)
    if config.bot_socket.exists():
        old = config.bot_socket.lstat()
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != 0:
            raise RuntimeError("unsafe existing bot socket")
        config.bot_socket.unlink()
    store = Store(config.state_path, config.audit_path, config.pending_ttl_seconds)
    executor = Executor(config, policy, store)
    await executor.reconcile()
    server = await asyncio.start_unix_server(executor.connection, str(config.bot_socket),
                                             limit=MAX_MESSAGE_BYTES + 1)
    os.chown(config.bot_socket, 0, executor.bot_gid)
    os.chmod(config.bot_socket, 0o660)

    async def sweeper() -> None:
        while True:
            await asyncio.sleep(5)
            await executor.reconcile()

    task = asyncio.create_task(sweeper())
    try:
        async with server:
            await server.serve_forever()
    finally:
        task.cancel()
        store.close()
        config.bot_socket.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Deadbolt root executor")
    parser.add_argument("--config", type=Path, default=Path("/etc/deadbolt/executor.toml"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if os.geteuid() != 0:
        raise RuntimeError("executor must run as root")
    _secure_root_path(args.config)
    config = ExecutorConfig.load(args.config)
    _secure_root_path(config.profiles_path)
    policy = Policy.load(config.profiles_path)
    asyncio.run(serve(config, policy))


if __name__ == "__main__":
    main()
