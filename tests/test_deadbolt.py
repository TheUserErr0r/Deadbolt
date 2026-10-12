"""Security invariants and recovery behavior without production services."""

from __future__ import annotations

import asyncio
import ast
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from deadbolt.actions import ActionError, UfwAction
from deadbolt.bot import BotConfig, Relay, handle_approval_button
from deadbolt.config import ConfigurationError, ExecutorConfig, FirewallProfile, Policy, resolve_action
from deadbolt.executor import Executor
from deadbolt.protocol import (INBOUND_MESSAGE_TIMEOUT_SECONDS, ProtocolError,
                               decode_message, peer_uid, read_message, require_fields)
from deadbolt.store import StateError, Store


def config(base: Path) -> ExecutorConfig:
    return ExecutorConfig(base / "state.db", base / "audit.jsonl", base / "bot.sock",
                          base / "profiles.toml", "deadbolt", "hermes", "1", "2", "3")


def policy() -> Policy:
    test_net = str(ipaddress.IPv4Network((0xC0000200, 24)))
    return Policy({"test-ssh": FirewallProfile("test-ssh", "out", "tcp", "any",
                                               test_net, "22", None, 1800)})


def canonical(base: Path, ttl: int | None = 900) -> dict[str, object]:
    return resolve_action("firewall_profile", "test-ssh", "Need test access", ttl, policy(), config(base))


class FakeUfw:
    def __init__(self):
        self.rules: list[list[str]] = []
        self.calls: list[list[str]] = []
        self.fail_next_allow = False
        self.active = True
        self.normalize_rules = False

    def _stored_rule(self, command: list[str]) -> list[str]:
        if not self.normalize_rules:
            return command
        # UFW 0.36 rewrites this test profile into the order shown by
        # `ufw show added`, regardless of the argv order used to add it.
        comment = command[command.index("comment"):] if "comment" in command else []
        return ["allow", "out", "to", "192.0.2.0/24", "port", "22", "proto", "tcp", *comment]

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv[:])
        command = argv[1:]
        if command == ["show", "added"]:
            import shlex
            output = "\n".join("ufw " + shlex.join(rule) for rule in self.rules)
            return subprocess.CompletedProcess(argv, 0, output, "")
        if command == ["status"]:
            return subprocess.CompletedProcess(argv, 0, "Status: active\n" if self.active else "Status: inactive\n", "")
        if command[:1] == ["allow"]:
            if self.fail_next_allow:
                self.fail_next_allow = False
                return subprocess.CompletedProcess(argv, 1, "", "simulated failure")
            self.rules.append(self._stored_rule(command))
            return subprocess.CompletedProcess(argv, 0, "", "")
        if command[:1] == ["delete"]:
            rule = self._stored_rule(command[1:])
            if rule in self.rules:
                self.rules.remove(rule)
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", "missing")
        return subprocess.CompletedProcess(argv, 1, "", "unexpected command")


class ProtocolTests(unittest.TestCase):
    def test_version_json_framing_and_schema(self) -> None:
        self.assertEqual(decode_message(b'{"version":1,"op":"status"}\n')["op"], "status")
        for raw in (b'{}\n', b'{"version":true}\n', b'{"version":2}\n', b'bad\n', b'{}',
                    b'{"version":1,"op":"a","op":"b"}\n',
                    b'{"version":1}\n' + b'x' * 16_384):
            with self.subTest(raw=raw[:20]), self.assertRaises(ProtocolError):
                decode_message(raw)
        with self.assertRaises(ProtocolError):
            require_fields({"version": 1, "op": "submit", "command": "id"}, {"op"})

    def test_linux_peer_credentials(self) -> None:
        fake = SimpleNamespace(getsockopt=lambda level, option, size: struct.pack("3i", 123, 456, 789))
        self.assertEqual(peer_uid(fake), 456)

    def test_inbound_message_read_still_uses_five_second_deadline(self) -> None:
        self.assertEqual(INBOUND_MESSAGE_TIMEOUT_SECONDS, 5)
        async def receive() -> None:
            await read_message(asyncio.StreamReader())

        with patch("deadbolt.protocol.asyncio.wait_for", side_effect=asyncio.TimeoutError) as wait:
            with self.assertRaisesRegex(ProtocolError, "message read failed"):
                asyncio.run(receive())
            self.assertEqual(wait.call_args.kwargs["timeout"], 5)
            wait.call_args.args[0].close()


class DiscordButtonTests(unittest.IsolatedAsyncioTestCase):
    async def test_approved_interaction_uses_posted_card_and_updates_message(self) -> None:
        relay = SimpleNamespace(decide_posted=AsyncMock(return_value={"id": "request-1", "status": "active"}))
        interaction = SimpleNamespace(
            id=55, user=SimpleNamespace(id=1), guild_id=2, channel_id=3,
            message=SimpleNamespace(id=44, edit=AsyncMock()),
            response=SimpleNamespace(send_message=AsyncMock(), defer=AsyncMock()),
            followup=SimpleNamespace(send=AsyncMock()))
        row = {"id": "request-1", "nonce": "nonce"}
        await handle_approval_button(relay, row, interaction, "approve", lambda _: True,
                                     lambda updated: updated["status"])
        relay.decide_posted.assert_awaited_once_with(row, "approve", "44", "55", "1", "2", "3")
        interaction.message.edit.assert_awaited_once_with(embed="active", view=None)
        interaction.followup.send.assert_awaited_once_with("Request request-1: active", ephemeral=True)

    async def test_unauthorized_interaction_never_reaches_executor(self) -> None:
        relay = SimpleNamespace(decide_posted=AsyncMock())
        interaction = SimpleNamespace(message=SimpleNamespace(id=44),
                                      response=SimpleNamespace(send_message=AsyncMock()))
        await handle_approval_button(relay, {"id": "request-1"}, interaction, "approve",
                                     lambda _: False, lambda _: None)
        relay.decide_posted.assert_not_awaited()
        interaction.response.send_message.assert_awaited_once_with(
            "Not authorized for this approval.", ephemeral=True)


class PolicyTests(unittest.TestCase):
    def test_strict_profile_and_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            self.assertEqual(canonical(base, 7200)["ttl_seconds"], 1800)
            self.assertEqual(canonical(base, None)["ttl_seconds"], 1800)
            for action, profile, ttl in (("service_state", "test-ssh", 1),
                                         ("teleport_identity", "test-ssh", 1),
                                         ("firewall_profile", "unknown", 1),
                                         ("firewall_profile", "test-ssh", -1)):
                with self.subTest(action=action, profile=profile, ttl=ttl), self.assertRaises(ConfigurationError):
                    resolve_action(action, profile, "reason", ttl, policy(), config(base))
            with self.assertRaises(ConfigurationError):
                FirewallProfile.from_mapping("bad", {"direction": "in", "protocol": "tcp",
                    "source": "any", "destination": "any", "port": "1:1000", "max_ttl_seconds": 100})
            with self.assertRaises(ConfigurationError):
                FirewallProfile.from_mapping("too-broad", {"direction": "out", "protocol": "tcp",
                    "source": "any", "destination": "any", "port": 443, "max_ttl_seconds": 100})


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.store = Store(self.base / "state.db", self.base / "audit.jsonl")
        self.request = self.store.create(canonical(self.base), "exact card", 102, 1000)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_nonce_replay_tampering_and_discord_scope(self) -> None:
        row = self.store.mark_posted(self.request["id"], "44", 1001)
        args = (row["id"], "approve", row["nonce"], row["canonical_hash"], "1", "2", "3", "44", "55", ("1", "2", "3"), 1002)
        with self.assertRaises(StateError):
            self.store.decide(*args[:3], "0" * 64, *args[4:])
        with self.assertRaises(StateError):
            self.store.decide(*args[:5], "wrong", *args[6:])
        with self.assertRaises(StateError):
            self.store.decide(*args[:7], "999", *args[8:])
        approved = self.store.decide(*args)
        self.assertEqual(approved["status"], "approved")
        with self.assertRaises(StateError):
            self.store.decide(*args)

    def test_expiry_and_audit_outbox(self) -> None:
        self.assertEqual(self.store.expire_pending(1600), 1)
        self.assertEqual(self.store.get(self.request["id"])["status"], "expired")
        self.assertEqual(self.store.flush_audit(), 2)
        lines = [json.loads(line) for line in (self.base / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([line["event"] for line in lines], ["request_created", "approval_expired"])
        self.assertEqual(self.store.flush_audit(), 0)


class UfwTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.fake = FakeUfw()
        self.action = UfwAction(self.fake)
        self.request = canonical(self.base)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_tagged_apply_and_idempotent_rollback(self) -> None:
        intent = self.action.prepare(self.request, "00000000-0000-4000-8000-000000000001")
        self.assertEqual(intent["mutation"], "tagged")
        self.action.apply(self.request, intent)
        self.assertEqual(len(self.fake.rules), 1)
        self.assertIn("deadbolt:", " ".join(self.fake.rules[0]))
        self.action.rollback(self.request, intent)
        self.action.rollback(self.request, intent)
        self.assertEqual(self.fake.rules, [])
        self.assertTrue(all(call[0] == "/usr/sbin/ufw" for call in self.fake.calls))
        self.assertFalse(any("Need test access" in " ".join(call) for call in self.fake.calls))

    def test_real_ufw_normalized_output_round_trip(self) -> None:
        self.fake.normalize_rules = True
        intent = self.action.prepare(self.request, "00000000-0000-4000-8000-000000000001")
        self.action.apply(self.request, intent)
        self.assertEqual(self.fake.rules[0][:-2],
                         ["allow", "out", "to", "192.0.2.0/24", "port", "22", "proto", "tcp"])
        self.action.rollback(self.request, intent)
        self.assertEqual(self.fake.rules, [])

    def test_inbound_and_interface_rule_formats(self) -> None:
        inbound = {**self.request, "direction": "in", "source": "192.0.2.1/32",
                   "destination": "any", "port": "443"}
        self.assertEqual(self.action._rule(inbound),
                         ["allow", "from", "192.0.2.1", "to", "any", "port", "443", "proto", "tcp"])
        interface = {**self.request, "interface": "eth0", "protocol": "udp",
                     "destination": "2001:db8::/64", "port": "8000:8002"}
        self.assertEqual(self.action._rule(interface),
                         ["allow", "out", "on", "eth0", "to", "2001:db8::/64",
                          "port", "8000:8002", "proto", "udp"])

    def test_singleton_cidr_matches_ufw_display_and_rolls_back(self) -> None:
        request = {**self.request, "destination": "192.0.2.5/32"}
        self.assertEqual(self.action._rule(request),
                         ["allow", "out", "to", "192.0.2.5", "port", "22", "proto", "tcp"])
        intent = self.action.prepare(request, "00000000-0000-4000-8000-000000000001")
        self.action.apply(request, intent)
        self.action.rollback(request, intent)
        self.assertFalse(self.fake.rules)

    def test_existing_rule_is_untouched(self) -> None:
        rule = self.action._rule(self.request)
        self.fake.rules.append(rule + ["comment", "operator rule"])
        intent = self.action.prepare(self.request, "00000000-0000-4000-8000-000000000001")
        self.assertEqual(intent["mutation"], "none")
        self.action.apply(self.request, intent)
        self.action.rollback(self.request, intent)
        self.assertEqual(self.fake.rules, [rule + ["comment", "operator rule"]])

    def test_inactive_ufw_fails_closed(self) -> None:
        self.fake.active = False
        with self.assertRaises(ActionError):
            self.action.prepare(self.request, "00000000-0000-4000-8000-000000000001")

    def test_changed_tag_fails_closed(self) -> None:
        intent = self.action.prepare(self.request, "00000000-0000-4000-8000-000000000001")
        self.action.apply(self.request, intent)
        self.fake.rules[0][-1] = "operator changed"
        with self.assertRaises(ActionError):
            self.action.rollback(self.request, intent)


class ExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.store = Store(self.base / "state.db", self.base / "audit.jsonl")
        self.fake = FakeUfw()
        self.action = UfwAction(self.fake)
        self.now = 1000.0
        lookup = lambda name: SimpleNamespace(pw_uid=101 if name == "deadbolt" else 102,
                                              pw_gid=201 if name == "deadbolt" else 202)
        self.patch = patch("deadbolt.executor.pwd.getpwnam", side_effect=lookup)
        self.patch.start()
        self.executor = Executor(config(self.base), policy(), self.store, self.action,
                                 lambda: self.now, policy_loader=policy)

    def tearDown(self) -> None:
        self.patch.stop()
        self.executor.close()
        self.store.close()
        self.temp.cleanup()

    def call(self, payload: dict[str, object], uid: int = 101) -> dict[str, object]:
        return asyncio.run(self.executor.dispatch({"version": 1, **payload}, uid))

    def test_bot_socket_group_uses_gid(self) -> None:
        self.assertEqual(self.executor.bot_uid, 101)
        self.assertEqual(self.executor.bot_gid, 201)

    def test_uid_and_request_tampering(self) -> None:
        payload = {"op": "create", "action": "firewall_profile", "profile": "test-ssh",
                   "reason": "Need test access", "requested_by_uid": 102}
        with self.assertRaises(ProtocolError):
            self.call(payload, uid=102)
        with self.assertRaises(ProtocolError):
            self.call({**payload, "requested_by_uid": 101})
        with self.assertRaises(ProtocolError):
            self.call({**payload, "port": 4444})
        with self.assertRaises(ConfigurationError):
            self.call({**payload, "profile": "unknown"})

    def test_approval_apply_expire_and_reconcile(self) -> None:
        created = self.call({"op": "create", "action": "firewall_profile", "profile": "test-ssh",
                             "reason": "Need test access", "requested_by_uid": 102})["request"]
        request_id = created["id"]
        pending = self.call({"op": "list", "state": "pending"})["requests"][0]
        self.call({"op": "posted", "request_id": request_id, "message_id": "44"})
        decision = {"op": "decide", "request_id": request_id, "decision": "approve",
                    "nonce": pending["nonce"], "canonical_hash": pending["canonical_hash"],
                    "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44", "interaction_id": "55"}
        self.now = 1005
        active = self.call(decision)["request"]
        self.assertEqual(active["status"], "active")
        self.assertEqual(len(self.fake.rules), 1)
        with self.assertRaises(StateError):
            self.call(decision)
        self.now = 2806
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(request_id)["status"], "rolled_back")
        self.assertEqual(self.fake.rules, [])

    def test_restart_rolls_back_interrupted_execution(self) -> None:
        row = self.store.create(canonical(self.base), "exact card", 102, self.now)
        self.store.mark_posted(row["id"], "44", self.now)
        self.store.decide(row["id"], "approve", row["nonce"], row["canonical_hash"],
                          "1", "2", "3", "44", "55", ("1", "2", "3"), self.now)
        intent = self.action.prepare(canonical(self.base), row["id"])
        self.store.mark_executing(row["id"], intent, self.now)
        self.action.apply(canonical(self.base), intent)
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "failed")
        self.assertEqual(self.fake.rules, [])

    def test_apply_failure_is_audited_without_active_grant(self) -> None:
        created = self.call({"op": "create", "action": "firewall_profile", "profile": "test-ssh",
                             "reason": "Need test access", "requested_by_uid": 102})["request"]
        pending = self.call({"op": "list", "state": "pending"})["requests"][0]
        self.call({"op": "posted", "request_id": created["id"], "message_id": "44"})
        self.fake.fail_next_allow = True
        with patch("deadbolt.executor.LOG.exception"):
            result = self.call({"op": "decide", "request_id": created["id"], "decision": "approve",
                                "nonce": pending["nonce"], "canonical_hash": pending["canonical_hash"],
                                "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
                                "interaction_id": "55"})["request"]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.fake.rules, [])
        events = [json.loads(line)["event"] for line in (self.base / "audit.jsonl").read_text().splitlines()]
        self.assertIn("execution_failed", events)

    def test_policy_changed_before_approval_fails_closed(self) -> None:
        created = self.call({"op": "create", "action": "firewall_profile", "profile": "test-ssh",
                             "reason": "Need test access", "requested_by_uid": 102})["request"]
        pending = self.call({"op": "list", "state": "pending"})["requests"][0]
        self.call({"op": "posted", "request_id": created["id"], "message_id": "44"})
        self.executor.policy_loader = lambda: Policy({})
        with self.assertRaises(ConfigurationError):
            self.call({"op": "decide", "request_id": created["id"], "decision": "approve",
                       "nonce": pending["nonce"], "canonical_hash": pending["canonical_hash"],
                       "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
                       "interaction_id": "55"})
        self.assertEqual(self.store.get(created["id"])["status"], "posted")
        self.assertEqual(self.fake.rules, [])

    def test_failed_rollback_stays_recoverable(self) -> None:
        created = self.call({"op": "create", "action": "firewall_profile", "profile": "test-ssh",
                             "reason": "Need test access", "requested_by_uid": 102})["request"]
        pending = self.call({"op": "list", "state": "pending"})["requests"][0]
        self.call({"op": "posted", "request_id": created["id"], "message_id": "44"})
        self.call({"op": "decide", "request_id": created["id"], "decision": "approve",
                   "nonce": pending["nonce"], "canonical_hash": pending["canonical_hash"],
                   "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
                   "interaction_id": "55"})
        tag = self.fake.rules[0][-1]
        self.fake.rules[0][-1] = "operator changed"
        self.now = 2801
        with patch("deadbolt.executor.LOG.exception"):
            asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(created["id"])["status"], "active")
        self.fake.rules[0][-1] = tag
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(created["id"])["status"], "rolled_back")


class RelayTests(unittest.TestCase):
    def test_hermes_uid_and_schema(self) -> None:
        sent: list[dict[str, object]] = []

        async def fake_rpc(path: str, payload: dict[str, object]) -> dict[str, object]:
            sent.append(payload)
            return {"ok": True, "request": {"id": "one"}}

        cfg = BotConfig(Path("/tmp/hermes.sock"), Path("/tmp/bot.sock"), "hermes", "1", "2", "3", None, True)
        with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=102)):
            relay = Relay(cfg, fake_rpc)
        message = {"version": 1, "op": "submit", "action": "firewall_profile",
                   "profile": "test-ssh", "reason": "Need test access"}
        with self.assertRaises(ProtocolError):
            asyncio.run(relay.submit(message, 101))
        with self.assertRaises(ProtocolError):
            asyncio.run(relay.submit({**message, "command": "id"}, 102))
        asyncio.run(relay.submit(message, 102))
        self.assertEqual(sent[0]["requested_by_uid"], 102)
        self.assertNotIn("command", sent[0])

    def test_new_card_decision_uses_posted_message_id(self) -> None:
        sent: list[dict[str, object]] = []
        card = {"id": "request-one", "nonce": "one-time", "canonical_hash": "hash",
                "posted_message_id": None}
        posted = {**card, "posted_message_id": "44"}

        async def fake_rpc(path: str, payload: dict[str, object]) -> dict[str, object]:
            sent.append(payload)
            if payload["op"] == "list":
                return {"ok": True, "requests": [posted]}
            return {"ok": True, "request": {"status": "active"}}

        cfg = BotConfig(Path("/tmp/hermes.sock"), Path("/tmp/bot.sock"), "hermes", "1", "2", "3", None, True)
        with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=102)):
            relay = Relay(cfg, fake_rpc)
        result = asyncio.run(relay.decide_posted(card, "approve", "44", "55", "1", "2", "3"))
        self.assertEqual(result["status"], "active")
        self.assertEqual(sent[-1]["message_id"], "44")
        with self.assertRaises(ProtocolError):
            asyncio.run(relay.decide_posted(card, "approve", "45", "56", "1", "2", "3"))


class StaticSafetyTests(unittest.TestCase):
    def test_no_shell_execution_or_dynamic_command_entrypoint(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "deadbolt"
        for path in root.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        keywords = {item.arg: item.value for item in node.keywords}
                        self.assertIn("shell", keywords, path)
                        self.assertIsInstance(keywords["shell"], ast.Constant)
                        self.assertIs(keywords["shell"].value, False)


if __name__ == "__main__":
    unittest.main()
