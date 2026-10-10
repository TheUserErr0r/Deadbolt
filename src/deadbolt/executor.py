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
from typing import Any, Callable

from deadbolt.actions import ActionError, UfwAction
from deadbolt.config import ConfigurationError, ExecutorConfig, Policy, resolve_action
from deadbolt.protocol import MAX_MESSAGE_BYTES, ProtocolError, peer_uid, read_message, require_fields, write_message
from deadbolt.store import StateError, Store, canonical_json

LOG = logging.getLogger(__name__)


class Executor:
    def __init__(self, config: ExecutorConfig, policy: Policy, store: Store,
                 action: UfwAction | None = None, clock: Callable[[], float] = time.time,
                 policy_loader: Callable[[], Policy] | None = None):
        self.config = config
        self.policy = policy
        self.policy_loader = policy_loader or (lambda: Policy.load(config.profiles_path))
        self.store = store
        self.action = action or UfwAction()
        self.clock = clock
        self.lock = asyncio.Lock()
        self.bot_uid = pwd.getpwnam(config.bot_user).pw_uid
        self.hermes_uid = pwd.getpwnam(config.hermes_user).pw_uid

    def _revalidate(self, row: Any) -> dict[str, Any]:
        original = json.loads(row["canonical_json"])
        current = resolve_action(original["action"], original["profile"], original["reason"],
                                 original["ttl_seconds"], self.policy_loader(), self.config)
        if (canonical_json(current) != row["canonical_json"] or
                hashlib.sha256(row["canonical_json"].encode()).hexdigest() != row["canonical_hash"]):
            raise StateError("stored action no longer matches root policy")
        self.action.validate(current)
        return current

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
            require_fields(message, {"op", "action", "profile", "reason", "requested_by_uid"}, {"ttl_seconds"})
            if type(message["requested_by_uid"]) is not int or message["requested_by_uid"] != self.hermes_uid:
                raise ProtocolError("invalid claimed request origin")
            if not all(isinstance(message[key], str) for key in ("action", "profile", "reason")):
                raise ProtocolError("invalid request fields")
            canonical = resolve_action(message["action"], message["profile"], message["reason"],
                                       message.get("ttl_seconds"), self.policy_loader(), self.config)
            self.action.validate(canonical)
            row = self.store.create(canonical, self.action.describe(canonical), self.hermes_uid, now)
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
        raise ProtocolError("unknown operation")

    async def _execute(self, row: Any) -> Any:
        request_id = row["id"]
        now = self.clock()
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
            for row in self.store.recovery_rows(now):
                if row["status"] == "approved":
                    self.store.mark_failed(row["id"], "executor stopped before apply", self.clock())
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
    os.chown(config.bot_socket, 0, executor.bot_uid)
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
