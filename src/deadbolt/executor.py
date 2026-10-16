"""Root executor: the only component permitted to change host policy."""

from __future__ import annotations

import argparse
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import hashlib
import ipaddress
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
from deadbolt.access import AccessError, canonical_access, command_argv, describe_access, destination
from deadbolt.broker_firewall import BrokerFirewall, BrokerFirewallError
from deadbolt.outbound import OutboundError, canonical_outbound, describe_outbound
from deadbolt.outbound_firewall import ExactEgress, OutboundFirewallError
from deadbolt.ingress import IngressError, canonical_ingress, describe_ingress
from deadbolt.ingress_firewall import IngressFirewall, IngressFirewallError
from deadbolt.proxy_manager import ProxyManager, ProxyError
from deadbolt.config import ConfigurationError, ExecutorConfig, Policy, describe_action, normalize_workload_units, resolve_action
from deadbolt.protocol import MAX_MESSAGE_BYTES, ProtocolError, peer_uid, read_message, require_fields, write_message
from deadbolt.store import StateError, Store, canonical_json
from deadbolt.ssh_exec import MAX_HERMES_OUTPUT_BYTES, MAX_OUTPUT_BYTES, SystemdSSHExecutor

LOG = logging.getLogger(__name__)
HOST_WORKER_WAKE_SECONDS = 0.25


def _hermes_ssh_output(result: dict[str, Any]) -> dict[str, Any]:
    """Return a small byte-exact prefix only after restricted evidence is durable."""
    response: dict[str, Any] = {"output_encoding": "base64"}
    for stream in ("stdout", "stderr"):
        encoded = result[stream + "_b64"]
        if not isinstance(encoded, str):
            raise StateError("SSH result is missing restricted output")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise StateError("SSH result output encoding is invalid") from exc
        if len(data) > MAX_OUTPUT_BYTES or type(result[stream + "_truncated"]) is not bool:
            raise StateError("SSH result output exceeds policy")
        response[stream + "_b64"] = base64.b64encode(data[:MAX_HERMES_OUTPUT_BYTES]).decode("ascii")
        response[stream + "_truncated"] = (result[stream + "_truncated"]
                                           or len(data) > MAX_HERMES_OUTPUT_BYTES)
    return response


class Executor:
    def __init__(self, config: ExecutorConfig, policy: Policy, store: Store,
                 action: UfwAction | None = None, clock: Callable[[], float] = time.time,
                 policy_loader: Callable[[], Policy] | None = None,
                 capture_action: CaptureAction | None = None,
                 exclusions_action: ExclusionsAction | None = None,
                 emergency_action: EmergencyAction | None = None,
                 access_action: BrokerFirewall | None = None,
                 ssh_executor: SystemdSSHExecutor | None = None,
                 outbound_firewall: ExactEgress | None = None,
                 proxy_manager: ProxyManager | None = None,
                 ingress_firewall: IngressFirewall | None = None):
        self.config = config
        self.policy = policy
        self.policy_loader = policy_loader or (lambda: Policy.load(config.profiles_path))
        self.store = store
        self.action = action or UfwAction()
        try:
            broker_uid = pwd.getpwnam("deadbolt-ssh").pw_uid
        except KeyError:
            if policy.access_profiles:
                raise ConfigurationError("deadbolt-ssh account is required for access profiles")
            broker_uid = None
        self.access_action = access_action or (BrokerFirewall(broker_uid) if broker_uid and policy.access_profiles else None)
        self.ssh_executor = ssh_executor or SystemdSSHExecutor()
        proxy_uid = None
        if policy.outbound_access.enabled or store.active_outbound_rows():
            try:
                proxy_uid = pwd.getpwnam("deadbolt-ssh-proxy").pw_uid
            except KeyError as exc:
                if outbound_firewall is None:
                    raise ConfigurationError("deadbolt-ssh-proxy account is required") from exc
        self.outbound_firewall = outbound_firewall or (
            ExactEgress(pwd.getpwnam(config.hermes_user).pw_uid, proxy_uid)
            if proxy_uid is not None else None)
        self.ingress_firewall = ingress_firewall or (
            IngressFirewall() if policy.ingress_access.enabled or store.active_ingress_rows() else None)
        self.proxy_manager = proxy_manager or ProxyManager()
        self.capture_action = capture_action or CaptureAction()
        self.exclusions_action = exclusions_action or ExclusionsAction()
        self.clock = clock
        self.lock = asyncio.Lock()
        self.emergency_lock = asyncio.Lock()
        bot_account = pwd.getpwnam(config.bot_user)
        self.bot_uid = bot_account.pw_uid
        self.bot_gid = bot_account.pw_gid
        self.hermes_uid = pwd.getpwnam(config.hermes_user).pw_uid
        self.emergency_action = emergency_action or EmergencyAction(self.hermes_uid,
            broker_uid=broker_uid, proxy_uid=proxy_uid)
        self.host_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="deadbolt-host")
        self.emergency_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="deadbolt-emergency")

    async def _pool_call(self, pool: ThreadPoolExecutor, func: Callable[..., Any], *args: Any) -> Any:
        future = asyncio.get_running_loop().run_in_executor(pool, partial(func, *args))
        # A timed wait keeps the event loop responsive even when a worker
        # completion notification is delayed. Shielding leaves the host
        # operation running until its own fixed subprocess deadline.
        while True:
            try:
                return await asyncio.wait_for(asyncio.shield(future), timeout=HOST_WORKER_WAKE_SECONDS)
            except asyncio.TimeoutError:
                continue

    async def _host_call(self, func: Callable[..., Any], *args: Any) -> Any:
        return await self._pool_call(self.host_pool, func, *args)

    async def _emergency_call(self, func: Callable[..., Any], *args: Any) -> Any:
        return await self._pool_call(self.emergency_pool, func, *args)

    def close(self) -> None:
        self.host_pool.shutdown(wait=False, cancel_futures=True)
        self.emergency_pool.shutdown(wait=False, cancel_futures=True)

    def _revalidate(self, row: Any) -> dict[str, Any]:
        original = json.loads(row["canonical_json"])
        capture = original["action"] == "proxy_body_capture"
        exclusions = original["action"] == "body_capture_exclusions"
        policy = self.policy_loader()
        if original["action"] == "emergency_recover":
            state = self.store.emergency_state()
            current = self._recovery_canonical(state, policy)
        elif original["action"] == "access_grant":
            profile = (policy.access_profiles or {}).get(original["profile"])
            if profile is None:
                raise StateError("access profile is no longer allowed")
            if profile.audit_output == "full" and self.store.restricted_ssh_audit_path is None:
                raise StateError("restricted SSH audit sink is not configured")
            current = canonical_access(profile, original["destination"], original["purpose"],
                                       original["ttl_seconds"], original["initial_command"])
        elif original["action"] == "outbound_access":
            current = canonical_outbound(policy.outbound_access, kind=original["kind"],
                destination=original["destination"], port=original["port"],
                ttl_seconds=original["ttl_seconds"], purpose=original["purpose"],
                transport=original["transport"] if original["kind"] == "raw" else None)
        elif original["action"] == "ingress_access":
            current = canonical_ingress(policy.ingress_access,
                protocol=original["protocol"], source_ip=original["source"],
                local_ip=original["local_ip"], port_start=original["port_start"],
                port_end=original["port_end"], ttl_seconds=original["ttl_seconds"],
                reason=original["reason"])
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
        if original["action"] not in ("emergency_recover", "access_grant", "outbound_access",
                                      "ingress_access"):
            (self.capture_action if capture else self.exclusions_action if exclusions else
             self.action).validate(current)
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
        if message.get("op") == "emergency_stop":
            async with self.emergency_lock:
                try:
                    return await self._emergency_stop(message)
                finally:
                    try:
                        self.store.flush_audit()
                    except OSError:
                        LOG.exception("audit JSONL flush failed; durable outbox will retry")
        async with self.lock:
            try:
                result = await self._dispatch_locked(message)
            finally:
                try:
                    self.store.flush_audit()
                except OSError:
                    LOG.exception("audit JSONL flush failed; durable outbox will retry")
            return result

    async def _emergency_stop(self, message: dict[str, Any]) -> dict[str, Any]:
        require_fields(message, {"op", "user_id", "guild_id", "channel_id", "interaction_id"})
        self._operator(message)
        now = self.clock()
        state = self.store.emergency_state()
        first_stop = state["state"] == "inactive"
        if first_stop:
            units = self.policy_loader().emergency_workload_units
            state = self.store.emergency_transition(("inactive",), "stopping",
                "emergency_stop_started", now, operator_id=message["user_id"],
                interaction_id=message["interaction_id"], workload_units=units,
                previously_active=(), next_generation=True)
        try:
            # Block both UIDs before touching a broker unit or a slow proxy.
            await self._emergency_call(self.emergency_action.install_block)
            failures: list[str] = []
            for outbound in self.store.active_outbound_rows():
                try:
                    outbound = self.store.begin_outbound_revoke(outbound["id"], self.clock(),
                                                               message["user_id"])
                    await self._revoke_outbound(outbound, emergency=True)
                    self.store.mark_outbound_revoked(outbound["id"], self.clock(),
                        message["user_id"], "emergency_stop; request a new grant")
                except Exception:
                    failures.append("outbound grant revocation failed")
            for ingress in self.store.active_ingress_rows():
                try:
                    ingress = self.store.begin_ingress_revoke(ingress["id"], self.clock(),
                                                               self.hermes_uid)
                    await self._revoke_ingress(ingress, emergency=True)
                    self.store.mark_ingress_revoked(ingress["id"], self.clock(),
                                                     self.hermes_uid, "emergency_stop")
                except Exception:
                    failures.append("ingress grant revocation failed")
            if first_stop:
                previous = await self._emergency_call(self.emergency_action.active_units, units)
                state = self.store.emergency_transition(("stopping",), "stopping",
                    "emergency_stop_units_recorded", self.clock(),
                    operator_id=message["user_id"], interaction_id=message["interaction_id"],
                    previously_active=previous)
            for execution in self.store.interrupted_access_executions():
                partial = None
                try:
                    partial = await self._emergency_call(self.ssh_executor.cancel,
                        execution["request_id"], execution["command_index"])
                except Exception:
                    failures.append("SSH unit cancellation failed")
                if self.store.access_execution_state(execution["id"]) == "started":
                    try:
                        self.store.interrupt_access_execution(execution["id"], self.clock(), partial)
                    except Exception:
                        failures.append("SSH interruption evidence could not be queued")
            try:
                self.store.flush_restricted_audit()
            except Exception:
                failures.append("SSH interruption evidence delivery failed")
            for row in self.store.access_revoke_rows():
                try:
                    row = self.store.begin_access_revoke(row["id"], self.clock(), message["user_id"])
                    intent = json.loads(row["rollback_json"])
                    assert self.access_action is not None
                    await self._emergency_call(self.access_action.revoke,
                        intent["pinned_ip"], row["id"], intent["expiry"])
                    self.store.mark_revoked(row["id"], self.clock(), message["user_id"])
                except Exception:
                    self.store.rollback_error(row["id"], "emergency SSH revocation requires inspection", self.clock())
                    failures.append("SSH grant revocation failed")
            await self._emergency_call(self.emergency_action.enforce,
                tuple(state["workload_units"]))
            if self.store.access_revoke_rows():
                failures.append("active SSH grants remain")
            if failures:
                raise ActionError("; ".join(sorted(set(failures))))
        except Exception as exc:
            error = str(exc) if isinstance(exc, (ActionError, StateError, BrokerFirewallError)) else "internal emergency stop error"
            self.store.emergency_event("emergency_stop_failed", self.clock(),
                operator_id=message["user_id"], interaction_id=message["interaction_id"], error=error)
            raise ActionError(error) from exc
        if state["state"] != "active":
            state = self.store.emergency_transition(("stopping", "recovering"), "active",
                "emergency_stop_active", self.clock(), operator_id=message["user_id"],
                interaction_id=message["interaction_id"])
        else:
            self.store.emergency_event("emergency_stop_idempotent", self.clock(),
                operator_id=message["user_id"], interaction_id=message["interaction_id"])
        return {"ok": True, "emergency": {**state, "egress_block_enforced": True,
                                             "running_units": []}}

    async def _dispatch_locked(self, message: dict[str, Any]) -> dict[str, Any]:
        op = message.get("op")
        now = self.clock()
        if op == "create":
            require_fields(message, {"op", "action", "profile", "reason", "requested_by_uid"},
                           {"ttl_seconds", "hours", "destination", "purpose", "command",
                            "kind", "port", "transport", "protocol", "source_ip", "local_ip",
                            "port_start", "port_end"})
            if type(message["requested_by_uid"]) is not int or message["requested_by_uid"] != self.hermes_uid:
                raise ProtocolError("invalid claimed request origin")
            if not all(isinstance(message[key], str) for key in ("action", "profile", "reason")):
                raise ProtocolError("invalid request fields")
            if message["action"] == "access_grant":
                require_fields(message, {"op", "action", "profile", "reason", "requested_by_uid",
                                         "destination", "purpose", "ttl_seconds", "command"})
                if message["reason"] != message["purpose"]:
                    raise ProtocolError("access purpose mismatch")
                profile = (self.policy_loader().access_profiles or {}).get(message["profile"])
                if profile is None:
                    raise AccessError("access profile is not allowed")
                if self.access_action is None:
                    raise AccessError("SSH broker is not initialized; restart the executor")
                if profile.audit_output == "full" and self.store.restricted_ssh_audit_path is None:
                    raise AccessError("restricted SSH audit sink is not configured")
                canonical = canonical_access(profile, message["destination"], message["purpose"],
                                             message["ttl_seconds"], message.get("command"))
                description = describe_access(canonical)
            elif message["action"] == "outbound_access":
                required = {"op", "action", "profile", "reason", "requested_by_uid",
                            "kind", "destination", "port", "purpose", "ttl_seconds"}
                require_fields(message, required,
                    {"transport"} if message.get("kind") == "raw" else frozenset())
                if (message["reason"] != message["purpose"]
                        or message["profile"] != message["kind"]):
                    raise ProtocolError("outbound request fields disagree")
                if self.outbound_firewall is None:
                    raise OutboundError("outbound firewall is not configured")
                canonical = canonical_outbound(self.policy_loader().outbound_access,
                    kind=message["kind"], destination=message["destination"],
                    port=message["port"], ttl_seconds=message["ttl_seconds"],
                    purpose=message["purpose"], transport=message.get("transport"))
                description = describe_outbound(canonical)
            elif message["action"] == "ingress_access":
                require_fields(message, {"op", "action", "profile", "reason", "requested_by_uid",
                                         "protocol", "source_ip", "local_ip", "port_start", "port_end",
                                         "ttl_seconds"})
                if message["profile"] != "ingress" or self.ingress_firewall is None:
                    raise IngressError("ingress is not configured")
                canonical = canonical_ingress(self.policy_loader().ingress_access,
                    protocol=message["protocol"], source_ip=message["source_ip"],
                    local_ip=message["local_ip"], port_start=message["port_start"],
                    port_end=message["port_end"], ttl_seconds=message["ttl_seconds"],
                    reason=message["reason"])
                await self._host_call(self.ingress_firewall.assert_local_ip, canonical["local_ip"])
                description = describe_ingress(canonical)
            else:
                if set(message) & {"destination", "purpose", "command", "kind", "port", "transport",
                                   "protocol", "source_ip", "local_ip", "port_start", "port_end"}:
                    raise ProtocolError("unexpected access fields")
                canonical = resolve_action(message["action"], message["profile"], message["reason"],
                                           message.get("ttl_seconds"), self.policy_loader(), self.config,
                                           message.get("hours"))
                action = (self.capture_action if canonical["action"] == "proxy_body_capture" else
                          self.action)
                action.validate(canonical)
                description = action.describe(canonical)
            row = self.store.create(canonical, description, self.hermes_uid, now)
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
        if op in ("emergency_status", "emergency_recover_create"):
            require_fields(message, {"op", "user_id", "guild_id", "channel_id", "interaction_id"})
            self._operator(message)
            if op == "emergency_status":
                try:
                    enforced = await self._host_call(self.emergency_action.enabled)
                    state = self.store.emergency_state()
                    running = await self._host_call(self.emergency_action.active_units,
                                                       tuple(state["workload_units"]))
                except ActionError as exc:
                    self.store.emergency_event("emergency_status_failed", now,
                        operator_id=message["user_id"], interaction_id=message["interaction_id"],
                        error=str(exc))
                    raise
                self.store.emergency_event("emergency_status", now,
                    operator_id=message["user_id"], interaction_id=message["interaction_id"])
                return {"ok": True, "emergency": {**state, "egress_block_enforced": enforced,
                                                     "running_units": list(running)}}
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
        if op == "outbound_status":
            require_fields(message, {"op", "request_id", "requested_by_uid"})
            if message["requested_by_uid"] != self.hermes_uid:
                raise ProtocolError("invalid claimed request origin")
            row = self.store.get(message["request_id"])
            if row["action"] != "outbound_access" or row["requested_by_uid"] != self.hermes_uid:
                raise StateError("request is not a Hermes outbound grant")
            result = self.store.public(row)
            if row["status"] in ("revoked", "rolled_back", "failed"):
                result["guidance"] = "Access ended; request a new Zeus approval."
            return {"ok": True, "request": result}
        if op == "outbound_revoke":
            require_fields(message, {"op", "request_id", "user_id", "guild_id", "channel_id", "interaction_id"})
            self._operator(message)
            row = self.store.get(message["request_id"])
            if row["action"] != "outbound_access":
                raise StateError("request is not an outbound grant")
            if row["status"] in ("revoked", "rolled_back"):
                return {"ok": True, "request": self.store.public(row)}
            row = self.store.begin_outbound_revoke(row["id"], now, message["user_id"])
            await self._revoke_outbound(row)
            row = self.store.mark_outbound_revoked(row["id"], self.clock(), message["user_id"])
            return {"ok": True, "request": self.store.public(row)}
        if op == "ingress_status":
            require_fields(message, {"op", "requested_by_uid"})
            if type(message["requested_by_uid"]) is not int or message["requested_by_uid"] != self.hermes_uid:
                raise ProtocolError("invalid claimed request origin")
            rows = [row for row in self.store.active_ingress_rows()
                    if row["requested_by_uid"] == self.hermes_uid and row["status"] == "active"
                    and row["active_until"] is not None and row["active_until"] > now]
            return {"ok": True, "grants": [self.store.public(row) for row in rows]}
        if op == "ingress_revoke":
            require_fields(message, {"op", "request_id", "requested_by_uid"})
            if type(message["requested_by_uid"]) is not int or message["requested_by_uid"] != self.hermes_uid:
                raise ProtocolError("invalid claimed request origin")
            row = self.store.get(message["request_id"])
            if row["action"] != "ingress_access" or row["requested_by_uid"] != self.hermes_uid:
                raise StateError("request is not a Hermes ingress grant")
            if row["status"] in ("revoked", "expired", "rolled_back", "failed"):
                return {"ok": True, "request": self.store.public(row)}
            row = self.store.begin_ingress_revoke(row["id"], now, self.hermes_uid)
            await self._revoke_ingress(row)
            row = self.store.mark_ingress_revoked(row["id"], self.clock(), self.hermes_uid,
                                                  "requester")
            return {"ok": True, "request": self.store.public(row)}
        if op == "access_revoke":
            require_fields(message, {"op", "request_id", "user_id", "guild_id", "channel_id", "interaction_id"})
            self._operator(message)
            row = self.store.get(message["request_id"])
            if row["action"] != "access_grant":
                raise StateError("request is not a parameterized access grant")
            if row["status"] in ("revoked", "rolled_back"):
                return {"ok": True, "request": self.store.public(row)}
            if row["status"] not in ("active", "revoking"):
                raise StateError("access grant is not active")
            row = self.store.begin_access_revoke(row["id"], now, message["user_id"])
            try:
                canonical = json.loads(row["canonical_json"])
                intent = json.loads(row["rollback_json"])
                assert self.access_action is not None
                await self._host_call(self.access_action.revoke,
                    canonical["pinned_ips"][0], row["id"], intent["expiry"])
            except (BrokerFirewallError, OSError, ValueError) as exc:
                self.store.rollback_error(row["id"], str(exc), now)
                raise
            row = self.store.mark_revoked(row["id"], self.clock(), message["user_id"])
            return {"ok": True, "request": self.store.public(row)}
        if op == "access_execute":
            require_fields(message, {"op", "request_id", "requested_by_uid", "destination", "argv"})
            if type(message["requested_by_uid"]) is not int or message["requested_by_uid"] != self.hermes_uid:
                raise ProtocolError("invalid claimed request origin")
            if self.store.emergency_state()["state"] != "inactive":
                raise StateError("emergency stop blocks SSH execution")
            row = self.store.get(message["request_id"])
            if row["action"] != "access_grant" or row["status"] != "active" or row["active_until"] <= now:
                raise StateError("approved SSH grant is absent or expired")
            try:
                canonical = self._revalidate(row)
            except (AccessError, StateError, ConfigurationError):
                intent = json.loads(row["rollback_json"])
                assert self.access_action is not None
                try:
                    await self._host_call(self.access_action.revoke,
                        intent["pinned_ip"], row["id"], intent["expiry"])
                    self.store.mark_rolled_back(row["id"], self.clock())
                except Exception:
                    self.store.rollback_error(row["id"], "SSH policy drift requires grant inspection", self.clock())
                raise
            if destination(message["destination"])[0] != canonical["destination"]:
                raise StateError("SSH destination differs from approved session")
            command = command_argv(message["argv"],
                                   allow_sensitive=canonical["audit_output"] == "full")
            if command[0] not in canonical["remote_commands"]:
                raise StateError("command requires a new approval")
            if not canonical["audited_execution"] or len(canonical["pinned_ips"]) != 1:
                raise StateError("grant does not permit noninteractive SSH")
            intent = json.loads(row["rollback_json"])
            assert self.access_action is not None
            await self._host_call(self.access_action.assert_grant,
                canonical["pinned_ips"][0], row["id"], intent["expiry"])
            _, execution_id, command_index = self.store.begin_access_execution(row["id"], command, now)
            result = None
            hermes_output = None
            failure = None
            finished = False
            try:
                # The audit preflight must reach the root-owned JSONL file before SSH starts.
                if canonical["audit_output"] == "full":
                    self.store.flush_restricted_audit()
                self.store.flush_audit()
                result = await self._host_call(self.ssh_executor.execute, canonical,
                    row["id"], row["interaction_id"], command_index, command,
                    row["active_until"], self.clock())
                if canonical["audit_output"] == "full":
                    hermes_output = _hermes_ssh_output(result)
                if (self.store.emergency_state()["state"] != "inactive"
                        or self.store.get(row["id"])["status"] != "active"
                        or self.store.access_execution_state(execution_id) != "started"):
                    raise StateError("SSH command interrupted by emergency stop or grant revocation")
                self.store.finish_access_execution(execution_id, self.clock(), result)
                if canonical["audit_output"] == "full":
                    self.store.flush_restricted_audit()
                    self.store.finalize_access_execution(execution_id, self.clock())
                finished = True
                self.store.flush_audit()
                if result.get("timed_out"):
                    raise ActionError("SSH command timed out")
            except Exception as exc:
                try:
                    execution_state = self.store.access_execution_state(execution_id)
                except Exception:
                    execution_state = "unknown"
                evidence_pending = execution_state == "evidence_pending"
                failure = ("restricted SSH evidence delivery failed; inspect session"
                           if evidence_pending else str(exc) if isinstance(exc, (ActionError,
                               AccessError, StateError, OSError, TimeoutError))
                           else "internal SSH execution error")
                # An uncertain command or audit delivery failure closes the
                # session. Revoke first even if SQLite has become unwritable.
                revoked = False
                try:
                    await self._host_call(self.access_action.revoke,
                        intent["pinned_ip"], row["id"], intent["expiry"])
                    revoked = True
                except Exception:
                    LOG.exception("SSH grant revocation failed after command failure")
                try:
                    if not finished and execution_state in ("started", "evidence_pending"):
                        self.store.fail_access_execution(execution_id, self.clock(), failure)
                    if revoked and self.store.get(row["id"])["status"] in ("active", "executing"):
                        self.store.mark_rolled_back(row["id"], self.clock())
                    if evidence_pending or not revoked:
                        self.store.rollback_error(row["id"], failure if revoked else
                            "SSH grant revocation failed; inspect host", self.clock())
                except Exception:
                    LOG.exception("SSH failure state could not be persisted")
                    if not revoked:
                        failure = "SSH grant revocation failed; inspect host"
                if not revoked:
                    try:
                        self.store.rollback_error(row["id"],
                            "SSH grant revocation failed; inspect host", self.clock())
                    except Exception:
                        pass
            if failure is not None:
                raise ActionError(failure)
            assert result is not None
            ssh_result = {"request_id": row["id"], "exit_code": result["exit_code"],
                          "command_index": command_index, "finished_at": result["finished_at"]}
            if hermes_output is not None:
                ssh_result.update(hermes_output)
            return {"ok": True, "ssh": ssh_result}
        if op == "decide":
            required = {"op", "request_id", "decision", "nonce", "canonical_hash", "user_id",
                        "guild_id", "channel_id", "message_id", "interaction_id"}
            require_fields(message, required, {"raw_ssh_confirmed"})
            if any(not isinstance(message[key], str) for key in required - {"op"}):
                raise ProtocolError("invalid decision fields")
            row = self.store.get(message["request_id"])
            pending_canonical = json.loads(row["canonical_json"])
            raw_ssh = (row["action"] == "outbound_access"
                       and pending_canonical["kind"] == "raw"
                       and pending_canonical["transport"] == "tcp"
                       and pending_canonical["port"] == 22)
            if (message["decision"] == "approve" and raw_ssh
                    and message.get("raw_ssh_confirmed") is not True):
                raise ProtocolError("raw TCP/22 requires explicit uninspected SSH confirmation")
            if "raw_ssh_confirmed" in message and type(message["raw_ssh_confirmed"]) is not bool:
                raise ProtocolError("invalid raw SSH confirmation")
            try:
                self._revalidate(row)
            except (AccessError, OutboundError, IngressError, StateError, ActionError, ConfigurationError) as exc:
                if row["action"] in ("access_grant", "outbound_access", "ingress_access") and row["status"] in ("pending", "posted"):
                    self.store.invalidate_pending(row["id"], now, str(exc))
                raise
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

    async def _revoke_outbound(self, row: Any, *, emergency: bool = False) -> None:
        if self.outbound_firewall is None:
            raise OutboundFirewallError("outbound firewall is not configured")
        intent = json.loads(row["rollback_json"])
        call = self._emergency_call if emergency else self._host_call
        failures: list[str] = []
        try:
            await call(self.outbound_firewall.revoke, intent["kind"], intent["ip"],
                       intent["port"], intent["transport"], row["id"], intent["expiry"])
        except Exception:
            failures.append("exact outbound firewall revocation failed")
        if intent["kind"] == "ssh":
            try:
                await call(self.proxy_manager.revoke, row["id"])
            except Exception:
                failures.append("SSH proxy session termination failed")
        if failures:
            self.store.rollback_error(row["id"], "; ".join(failures), self.clock())
            raise OutboundFirewallError("; ".join(failures))

    def _ingress_overlaps_active(self, canonical: dict[str, Any]) -> bool:
        source = ipaddress.ip_network(canonical["source"])
        for row in self.store.active_ingress_rows():
            other = json.loads(row["canonical_json"])
            if (other["protocol"] == canonical["protocol"]
                    and other["local_ip"] == canonical["local_ip"]
                    and canonical["port_start"] <= other["port_end"]
                    and other["port_start"] <= canonical["port_end"]
                    and source.overlaps(ipaddress.ip_network(other["source"]))):
                return True
        return False

    async def _revoke_ingress(self, row: Any, *, emergency: bool = False) -> None:
        if self.ingress_firewall is None:
            raise IngressFirewallError("ingress firewall is not initialized")
        if not row["rollback_json"]:
            raise StateError("ingress rollback intent is missing")
        canonical = json.loads(row["canonical_json"])
        intent = json.loads(row["rollback_json"])
        call = self._emergency_call if emergency else self._host_call
        try:
            await call(self.ingress_firewall.revoke, canonical, row["id"], intent["expiry"])
        except Exception:
            self.store.rollback_error(row["id"], "ingress rollback requires inspection", self.clock())
            raise

    async def _execute(self, row: Any) -> Any:
        request_id = row["id"]
        now = self.clock()
        if row["action"] == "ingress_access":
            try:
                if self.store.emergency_state()["state"] != "inactive":
                    raise StateError("emergency stop blocks ingress grants")
                canonical = self._revalidate(row)
                if self._ingress_overlaps_active(canonical):
                    raise StateError("an overlapping ingress grant is active")
                if self.ingress_firewall is None:
                    raise IngressFirewallError("ingress firewall is not initialized")
                expiry = int(self.clock() + canonical["ttl_seconds"])
                _set_name, tag = self.ingress_firewall._identity(request_id, expiry)
                intent = {"source": canonical["source"], "local_ip": canonical["local_ip"],
                          "protocol": canonical["protocol"], "port_start": canonical["port_start"],
                          "port_end": canonical["port_end"], "expiry": expiry, "tag": tag}
                self.store.mark_executing(request_id, intent, self.clock())
                await self._host_call(self.ingress_firewall.ensure_grant,
                                      canonical, request_id, expiry, self.clock())
                await self._host_call(self.ingress_firewall.assert_grant,
                                      canonical, request_id, expiry)
                if self.clock() >= expiry or self.store.emergency_state()["state"] != "inactive":
                    raise StateError("ingress grant interrupted before activation")
                return self.store.mark_active(request_id, self.clock(), active_until=expiry)
            except Exception as exc:
                current = self.store.get(request_id)
                if current["rollback_json"]:
                    try:
                        # Emergency stop can revoke the executing row while a
                        # host call is still creating its rule. Revoke again
                        # after that host call returns, even if the row has
                        # already reached a terminal state.
                        await self._revoke_ingress(current)
                    except Exception:
                        return self.store.get(request_id)
                if current["status"] not in ("approved", "executing"):
                    return self.store.get(request_id)
                failure = str(exc) if isinstance(exc, (IngressError, IngressFirewallError,
                    StateError, ConfigurationError)) else "internal ingress access error"
                return self.store.mark_failed(request_id, failure, self.clock())
        if row["action"] == "outbound_access":
            try:
                if self.store.emergency_state()["state"] != "inactive":
                    raise StateError("emergency stop blocks outbound grants")
                canonical = self._revalidate(row)
                policy = self.policy_loader().outbound_access
                if canonical["kind"] == "ssh" and any(
                    json.loads(item["canonical_json"])["kind"] == "ssh"
                    for item in self.store.active_outbound_rows()):
                    raise StateError("another recorded SSH grant is active")
                if self.outbound_firewall is None:
                    raise OutboundFirewallError("outbound firewall is not configured")
                expiry = int(self.clock() + canonical["ttl_seconds"])
                intent = {"kind": canonical["kind"], "ip": canonical["destination"],
                          "port": canonical["port"], "transport": canonical["transport"],
                          "uid": (self.outbound_firewall.proxy_uid if canonical["kind"] == "ssh"
                                  else self.hermes_uid),
                          "chain": self.outbound_firewall._chain(canonical["kind"],
                              canonical["port"], canonical["transport"]),
                          "tag": self.outbound_firewall._validated(canonical["destination"],
                              canonical["port"], canonical["transport"], request_id, expiry),
                          "expiry": expiry}
                if canonical["kind"] == "ssh":
                    intent["proxy_port"] = policy.proxy_port
                self.store.mark_executing(request_id, intent, self.clock())
                await self._host_call(self.outbound_firewall.ensure_grant,
                    canonical["kind"], canonical["destination"], canonical["port"],
                    canonical["transport"], request_id, expiry, self.clock())
                if canonical["kind"] == "ssh":
                    await self._host_call(self.proxy_manager.activate, policy, canonical,
                                          request_id, expiry)
                    await self._host_call(self.proxy_manager.assert_active, request_id, expiry)
                await self._host_call(self.outbound_firewall.assert_grant,
                    canonical["kind"], canonical["destination"], canonical["port"],
                    canonical["transport"], request_id, expiry)
                if self.store.emergency_state()["state"] != "inactive" or self.clock() >= expiry:
                    raise StateError("outbound grant interrupted before activation")
                return self.store.mark_active(request_id, self.clock(), active_until=expiry)
            except Exception as exc:
                if self.store.get(request_id)["status"] == "executing":
                    try:
                        await self._revoke_outbound(self.store.get(request_id))
                    except Exception:
                        return self.store.get(request_id)
                failure = (str(exc) if isinstance(exc, (StateError, OutboundError,
                           OutboundFirewallError, ProxyError)) else "internal outbound access error")
                return self.store.mark_failed(request_id, failure, self.clock())
        if row["action"] == "access_grant":
            try:
                if self.store.emergency_state()["state"] != "inactive":
                    raise StateError("emergency stop blocks SSH grants")
                canonical = self._revalidate(row)
                if canonical["audit_output"] == "full":
                    self.store.check_restricted_sink()
                expiry = int(self.clock() + canonical["ttl_seconds"])
                assert self.access_action is not None
                intent = {"pinned_ip": canonical["pinned_ips"][0], "expiry": expiry,
                          "tag": self.access_action._identity(request_id, expiry),
                          "broker_uid": self.access_action.uid}
                self.store.mark_executing(request_id, intent, self.clock())
                identity = await self._host_call(self.access_action.ensure_grant,
                    canonical["pinned_ips"][0], request_id, expiry, self.clock())
                if self.store.emergency_state()["state"] != "inactive":
                    raise StateError("emergency stop interrupted SSH grant")
                if identity["expiry"] != expiry:
                    raise BrokerFirewallError("broker grant expiry changed")
                if self.clock() >= expiry:
                    raise ActionError("access grant expired before activation")
                return self.store.mark_active(request_id, self.clock(), active_until=expiry)
            except Exception as exc:
                if not isinstance(exc, (ActionError, AccessError, BrokerFirewallError, StateError, OSError)):
                    LOG.exception("unexpected access grant failure")
                failure = str(exc) if isinstance(exc, (ActionError, AccessError, BrokerFirewallError,
                                                      StateError, OSError)) else "internal access error"
                if self.store.get(request_id)["status"] == "executing":
                    try:
                        assert self.access_action is not None
                        rollback = json.loads(self.store.get(request_id)["rollback_json"])
                        await self._host_call(self.access_action.revoke,
                            rollback["pinned_ip"], request_id, rollback["expiry"])
                    except Exception:
                        self.store.rollback_error(request_id, "access rollback requires inspection", self.clock())
                        return self.store.get(request_id)
                return self.store.mark_failed(request_id, failure, self.clock())
        if row["action"] == "emergency_recover":
            started = False
            try:
                canonical = self._revalidate(row)
                self.store.mark_executing(request_id, {"generation": canonical["generation"]}, now)
                started = True
                self.store.emergency_transition(("active",), "recovering",
                    "emergency_recovery_started", now,
                    operator_id=row["approved_by_discord_id"], request_id=request_id)
                await self._host_call(self.emergency_action.recover,
                    tuple(canonical["previously_active"]), tuple(canonical["workload_units"]))
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
                        await self._host_call(self.emergency_action.enforce,
                            tuple(json.loads(row["canonical_json"])["workload_units"]))
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
            if self.ingress_firewall is not None:
                await self._host_call(self.ingress_firewall.ensure_guard)
                for ingress in self.store.active_ingress_rows():
                    expiry = ingress["active_until"]
                    expired = expiry is not None and expiry <= now
                    emergency = self.store.emergency_state()["state"] != "inactive"
                    policy_changed = False
                    try:
                        self._revalidate(ingress)
                    except (IngressError, StateError, ConfigurationError):
                        policy_changed = True
                    if ingress["status"] in ("revoking", "executing") or expired or emergency or policy_changed:
                        if ingress["status"] in ("active", "executing"):
                            ingress = self.store.begin_ingress_revoke(ingress["id"], now,
                                                                        self.hermes_uid)
                        await self._revoke_ingress(ingress)
                        self.store.mark_ingress_revoked(ingress["id"], self.clock(),
                            self.hermes_uid, "expired" if expired else
                            "emergency_stop" if emergency else
                            "policy_changed" if policy_changed else "reconciliation")
                    else:
                        intent = json.loads(ingress["rollback_json"])
                        await self._host_call(self.ingress_firewall.ensure_grant,
                            json.loads(ingress["canonical_json"]), ingress["id"],
                            intent["expiry"], now)
            if self.outbound_firewall is not None:
                await self._host_call(self.outbound_firewall.ensure_guard)
                for outbound in self.store.active_outbound_rows():
                    intent = json.loads(outbound["rollback_json"])
                    expired = outbound["active_until"] is not None and outbound["active_until"] <= now
                    interrupted = self.store.emergency_state()["state"] != "inactive"
                    try:
                        self._revalidate(outbound)
                    except (OutboundError, StateError, ConfigurationError):
                        interrupted = True
                    if outbound["status"] == "revoking" or expired or interrupted:
                        if outbound["status"] == "active":
                            outbound = self.store.begin_outbound_revoke(outbound["id"], now,
                                                                        "reconciliation")
                        await self._revoke_outbound(outbound)
                        self.store.mark_outbound_revoked(outbound["id"], self.clock(),
                            "reconciliation", "expired or interrupted; request a new grant")
                        continue
                    if intent["kind"] == "ssh":
                        try:
                            await self._host_call(self.proxy_manager.assert_active,
                                outbound["id"], intent["expiry"])
                        except ProxyError:
                            outbound = self.store.begin_outbound_revoke(outbound["id"], now,
                                                                        "reconciliation")
                            await self._revoke_outbound(outbound)
                            self.store.mark_outbound_revoked(outbound["id"], self.clock(),
                                "reconciliation", "proxy unavailable; request a new grant")
                            continue
                    await self._host_call(self.outbound_firewall.ensure_grant,
                        intent["kind"], intent["ip"], intent["port"], intent["transport"],
                        outbound["id"], intent["expiry"], now)
            if self.access_action is not None:
                await self._host_call(self.access_action.ensure_guard)
                for execution in self.store.interrupted_access_executions():
                    if self.store.access_execution_state(execution["id"]) == "started":
                        self.store.interrupt_access_execution(execution["id"], self.clock(),
                            None, reason=("emergency_stop" if
                                self.store.emergency_state()["state"] != "inactive"
                                else "executor_restart"))
                    else:
                        self.store.fail_access_execution(execution["id"], self.clock(),
                            "SSH command interrupted by executor restart")
                    row = self.store.get(execution["request_id"])
                    if row["status"] == "active":
                        intent = json.loads(row["rollback_json"])
                        await self._host_call(self.access_action.revoke,
                            intent["pinned_ip"], row["id"], intent["expiry"])
                        self.store.mark_rolled_back(row["id"], self.clock())
                for row in self.store.failed_access_rows():
                    intent = json.loads(row["rollback_json"])
                    await self._host_call(self.access_action.revoke,
                        intent["pinned_ip"], row["id"], intent["expiry"])
                    self.store.mark_rolled_back(row["id"], self.clock())
                for row in self.store.active_access_rows():
                    if (row["active_until"] > now
                            and self.store.emergency_state()["state"] == "inactive"):
                        intent = json.loads(row["rollback_json"])
                        await self._host_call(self.access_action.ensure_grant,
                            intent["pinned_ip"], row["id"], intent["expiry"], now)
            emergency = self.store.emergency_state()
            emergency_restored = emergency["state"] == "inactive"
            if emergency["state"] != "inactive":
                try:
                    await self._emergency_call(self.emergency_action.enforce,
                                            tuple(emergency["workload_units"]))
                    for row in self.store.access_revoke_rows():
                        row = self.store.begin_access_revoke(row["id"], self.clock(), "emergency-recovery")
                        intent = json.loads(row["rollback_json"])
                        assert self.access_action is not None
                        await self._emergency_call(self.access_action.revoke,
                            intent["pinned_ip"], row["id"], intent["expiry"])
                        self.store.mark_revoked(row["id"], self.clock(), "emergency-recovery")
                    emergency_restored = True
                    if emergency["state"] != "active":
                        self.store.emergency_transition((emergency["state"],), "active",
                            "emergency_reconciled_to_stopped", self.clock())
                except (ActionError, BrokerFirewallError, ConfigurationError, StateError) as exc:
                    self.store.emergency_event("emergency_reconcile_failed", self.clock(),
                        error=str(exc))
                    LOG.exception("emergency switch reconciliation failed")
            for row in self.store.recovery_rows(now):
                if row["status"] == "revoking":
                    if row["action"] == "ingress_access":
                        await self._revoke_ingress(row)
                        self.store.mark_ingress_revoked(row["id"], self.clock(),
                            self.hermes_uid, "reconciliation")
                        continue
                    intent = json.loads(row["rollback_json"])
                    assert self.access_action is not None
                    await self._host_call(self.access_action.revoke,
                        intent["pinned_ip"], row["id"], intent["expiry"])
                    self.store.mark_revoked(row["id"], self.clock(),
                        intent.get("revoke_operator_id", "recovery"))
                    continue
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
                    if row["action"] == "access_grant":
                        assert self.access_action is not None
                        await self._host_call(self.access_action.revoke,
                            rollback["pinned_ip"], row["id"], rollback["expiry"])
                    elif row["action"] == "outbound_access":
                        await self._revoke_outbound(row)
                    elif row["action"] == "ingress_access":
                        await self._revoke_ingress(row)
                    else:
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
        except (ProtocolError, StateError, ConfigurationError, ActionError, AccessError,
                BrokerFirewallError, OutboundError, OutboundFirewallError,
                IngressError, IngressFirewallError, ProxyError, ValueError) as exc:
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
    if config.restricted_ssh_audit_path is not None:
        if config.restricted_ssh_audit_path == config.audit_path:
            raise RuntimeError("restricted SSH audit must use a separate file")
        _secure_root_path(config.restricted_ssh_audit_path)
    _secure_root_path(config.bot_socket.parent, directory=True)
    if config.bot_socket.exists():
        old = config.bot_socket.lstat()
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != 0:
            raise RuntimeError("unsafe existing bot socket")
        config.bot_socket.unlink()
    store = Store(config.state_path, config.audit_path, config.pending_ttl_seconds,
                  config.restricted_ssh_audit_path)
    executor = Executor(config, policy, store)
    await executor.reconcile()
    server = await asyncio.start_unix_server(executor.connection, str(config.bot_socket),
                                             limit=MAX_MESSAGE_BYTES + 1)
    os.chown(config.bot_socket, 0, executor.bot_gid)
    os.chmod(config.bot_socket, 0o660)

    async def sweeper() -> None:
        while True:
            await asyncio.sleep(5)
            try:
                await executor.reconcile()
            except Exception:
                LOG.exception("periodic reconciliation failed")

    task = asyncio.create_task(sweeper())
    try:
        async with server:
            await server.serve_forever()
    finally:
        task.cancel()
        executor.close()
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
