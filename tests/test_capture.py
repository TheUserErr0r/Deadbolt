"""Mocked integration checks for the external capture and exclusion contracts."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deadbolt.actions import ActionError, CaptureAction, ExclusionsAction
from deadbolt.bot import BotConfig, Relay
from deadbolt.config import ConfigurationError, ExecutorConfig, Policy, resolve_action
from deadbolt.executor import Executor
from deadbolt.protocol import ProtocolError
from deadbolt.store import StateError, Store


def config(base: Path) -> ExecutorConfig:
    return ExecutorConfig(base / "state.db", base / "audit.jsonl", base / "bot.sock",
                          base / "profiles.toml", "deadbolt", "hermes", "1", "2", "3")


def policy() -> Policy:
    return Policy({}, True, ("discord.com", "discordapp.com", "discordapp.net", "discordcdn.com"))


class FakeCapture:
    def __init__(self):
        self.calls: list[list[str]] = []
        self.expiry: str | None = None
        self.now = 1_780_000_000
        self.raw: str | None = None
        self.returncode = 0

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv[:])
        if self.raw is not None:
            return subprocess.CompletedProcess(argv, self.returncode, self.raw, "secret stderr")
        verb = argv[2]
        if verb == "enable":
            self.expiry = datetime.fromtimestamp(self.now + int(argv[3]) * 3600, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            outcome = "enabled"
        elif verb == "disable":
            self.expiry = None
            outcome = "disabled"
        else:
            outcome = "status"
        data = {"enabled": self.expiry is not None, "expires_at": self.expiry, "outcome": outcome}
        return subprocess.CompletedProcess(argv, 0, json.dumps(data, separators=(",", ":")) + "\n", "")


class CaptureAdapterTests(unittest.TestCase):
    def test_fixed_json_commands_and_idempotent_operator_actions(self) -> None:
        fake = FakeCapture()
        action = CaptureAction(fake)
        canonical = resolve_action("proxy_body_capture", "proxy_body_capture", "approved test", None,
                                   policy(), config(Path("/tmp")), 2)
        self.assertEqual(action.enable(canonical)["outcome"], "enabled")
        self.assertEqual(action.status()["outcome"], "status")
        self.assertEqual(action.disable()["outcome"], "disabled")
        self.assertEqual(action.disable()["outcome"], "disabled")
        self.assertEqual([call[1:3] for call in fake.calls],
                         [["--json", "enable"], ["--json", "status"],
                          ["--json", "disable"], ["--json", "disable"]])
        self.assertTrue(all(call[0] == "/usr/local/sbin/hermes-body-capture" for call in fake.calls))

    def test_malformed_or_secret_bearing_helper_output_is_never_reported(self) -> None:
        fake = FakeCapture()
        action = CaptureAction(fake)
        for raw in ('{"enabled":true,"expires_at":null,"outcome":"status","url":"secret"}',
                    'https://secret.example/path\n',
                    '{"enabled":true,"expires_at":"2026-02-30T01:00:00Z","outcome":"status"}',
                    '{"enabled":false,"expires_at":null,"outcome":"unexpected"}'):
            fake.raw = raw
            with self.subTest(raw=raw), self.assertRaises(ActionError) as failure:
                action.status()
            self.assertNotIn("secret", str(failure.exception))
            self.assertNotIn(raw, str(failure.exception))

    def test_outcome_and_ttl_fail_closed(self) -> None:
        with self.assertRaises(ConfigurationError):
            resolve_action("proxy_body_capture", "proxy_body_capture", "test", None,
                           policy(), config(Path("/tmp")), 25)
        with self.assertRaises(ConfigurationError):
            resolve_action("proxy_body_capture", "proxy_body_capture", "test", None,
                           Policy({}), config(Path("/tmp")), 1)
        fake = FakeCapture()
        fake.raw = '{"enabled":false,"expires_at":null,"outcome":"internal_error"}\n'
        fake.returncode = 1
        with self.assertRaisesRegex(ActionError, "internal_error"):
            CaptureAction(fake).status()


class CaptureExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.store = Store(self.base / "state.db", self.base / "audit.jsonl")
        self.fake = FakeCapture()
        self.now = 1_780_000_000.0
        self.fake.now = int(self.now)
        lookup = lambda name: SimpleNamespace(pw_uid=101 if name == "deadbolt" else 102,
                                              pw_gid=201 if name == "deadbolt" else 202)
        self.patch = patch("deadbolt.executor.pwd.getpwnam", side_effect=lookup)
        self.patch.start()
        self.executor = Executor(config(self.base), policy(), self.store, clock=lambda: self.now,
                                 policy_loader=policy, capture_action=CaptureAction(self.fake))

    def tearDown(self) -> None:
        self.patch.stop()
        self.executor.close()
        self.store.close()
        self.temp.cleanup()

    async def approve(self, hours: int = 2) -> dict:
        created = await self.executor.dispatch({"op": "create", "action": "proxy_body_capture",
            "profile": "proxy_body_capture", "reason": "test need", "hours": hours,
            "requested_by_uid": 102}, 101)
        row = self.store.get(created["request"]["id"])
        await self.executor.dispatch({"op": "posted", "request_id": row["id"], "message_id": "44"}, 101)
        return await self.executor.dispatch({"op": "decide", "request_id": row["id"],
            "decision": "approve", "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
            "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
            "interaction_id": "55"}, 101)

    def test_approval_reenable_replaces_expiry_and_timer_owns_cleanup(self) -> None:
        first = asyncio.run(self.approve())
        self.assertEqual(first["request"]["status"], "active")
        self.assertEqual(first["request"]["active_until"], self.now + 7200)
        self.assertIn("retained on Argus for 24 hours", first["request"]["description"])
        self.now += 600
        self.fake.now = int(self.now)
        second = asyncio.run(self.approve(1))
        self.assertEqual(second["request"]["active_until"], self.now + 3600)
        self.assertEqual(self.store.get(first["request"]["id"])["status"], "superseded")
        self.now += 4000
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(second["request"]["id"])["status"], "active")
        self.assertFalse(any(call[2] == "disable" for call in self.fake.calls))
        events = [json.loads(line) for line in (self.base / "audit.jsonl").read_text().splitlines()]
        active = [event for event in events if event["event"] == "grant_active"]
        self.assertEqual(len(active), 2)
        self.assertEqual(active[1]["approved_by_discord_id"], "1")
        self.assertEqual(active[1]["helper_outcome"], "enabled")

    def test_operator_status_disable_audited_and_hermes_cannot_invoke(self) -> None:
        asyncio.run(self.approve())
        scope = {"user_id": "1", "guild_id": "2", "channel_id": "3", "interaction_id": "66"}
        with self.assertRaises(ProtocolError):
            asyncio.run(self.executor.dispatch({"op": "capture_disable", **{**scope, "user_id": "9"}}, 101))
        with self.assertRaises(ProtocolError):
            asyncio.run(self.executor.dispatch({"op": "capture_disable", **scope}, 102))
        result = asyncio.run(self.executor.dispatch({"op": "capture_status", **scope}, 101))
        self.assertTrue(result["capture"]["enabled"])
        result = asyncio.run(self.executor.dispatch({"op": "capture_disable", **scope}, 101))
        self.assertFalse(result["capture"]["enabled"])
        self.assertEqual(asyncio.run(self.executor.dispatch({"op": "capture_disable", **scope}, 101))["capture"]["outcome"], "disabled")
        lines = [json.loads(line) for line in (self.base / "audit.jsonl").read_text().splitlines()]
        self.assertEqual(len([line for line in lines if line["event"] == "capture_disable"]), 2)
        self.assertNotIn("secret", (self.base / "audit.jsonl").read_text())

    def test_interrupted_capture_enable_is_audited_without_deadbolt_cleanup(self) -> None:
        canonical = resolve_action("proxy_body_capture", "proxy_body_capture", "test", None,
                                   policy(), config(self.base), 1)
        row = self.store.create(canonical, "capture card", 102, self.now)
        self.store.mark_posted(row["id"], "44", self.now)
        self.store.decide(row["id"], "approve", row["nonce"], row["canonical_hash"],
                          "1", "2", "3", "44", "55", ("1", "2", "3"), self.now)
        self.store.mark_executing(row["id"], {"external_expiry": True}, self.now)
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "failed")
        self.assertEqual(self.fake.calls, [])

    def test_failed_helper_outcome_is_audited_without_raw_output(self) -> None:
        self.fake.raw = '{"enabled":false,"expires_at":null,"outcome":"internal_error"}\n'
        self.fake.returncode = 1
        result = asyncio.run(self.approve(1))["request"]
        self.assertEqual(result["status"], "failed")
        events = [json.loads(line) for line in (self.base / "audit.jsonl").read_text().splitlines()]
        failure = next(event for event in events if event["event"] == "execution_failed")
        self.assertEqual(failure["helper_outcome"], "internal_error")
        self.assertNotIn("secret stderr", (self.base / "audit.jsonl").read_text())


class ExclusionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.path = self.base / "body-capture-exclusions.conf"
        self.path.write_text("# existing\ndiscord.com\n")
        self.path.chmod(0o640)
        self.action = ExclusionsAction(self.path, os.getgid(), os.getuid())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_allowlist_and_atomic_replacement(self) -> None:
        request = self.action.create_change("add", "discordcdn.com",
                                            policy().body_exclusion_allowed_hosts)
        intent = self.action.prepare(request)
        self.action.apply(request, intent)
        self.action.apply(request, intent)
        self.assertEqual(self.path.read_text(), ExclusionsAction.header + "discord.com\ndiscordcdn.com\n")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        for bad in ("example.com", "*.discord.com", "discord.com:443",
                    "https://discord.com", "192.0.2.1", "DISCORD.COM"):
            with self.subTest(bad=bad), self.assertRaises((ConfigurationError, ActionError)):
                self.action.create_change("add", bad, policy().body_exclusion_allowed_hosts)

    def test_external_edit_refuses_approved_replacement(self) -> None:
        request = self.action.create_change("remove", "discord.com",
                                            policy().body_exclusion_allowed_hosts)
        intent = self.action.prepare(request)
        self.path.write_text("# changed\ndiscord.com\n")
        with self.assertRaisesRegex(ActionError, "changed before apply"):
            self.action.apply(request, intent)

    def test_exclusion_change_requires_own_approval_and_redacts_reason(self) -> None:
        store = Store(self.base / "state.db", self.base / "audit.jsonl")
        lookup = lambda name: SimpleNamespace(pw_uid=101 if name == "deadbolt" else 102,
                                              pw_gid=201 if name == "deadbolt" else 202)
        try:
            with patch("deadbolt.executor.pwd.getpwnam", side_effect=lookup):
                executor = Executor(config(self.base), policy(), store, clock=lambda: 1000.0,
                                    policy_loader=policy, exclusions_action=self.action)
            request = {"op": "exclusion_create", "operation": "add", "hostname": "discordcdn.com",
                "user_id": "1", "guild_id": "2", "channel_id": "3", "interaction_id": "54"}
            created = asyncio.run(executor.dispatch(request, 101))["request"]
            self.assertEqual(self.path.read_text(), "# existing\ndiscord.com\n")
            with self.assertRaises(ProtocolError):
                asyncio.run(executor.dispatch(request, 102))
            with self.assertRaises(ProtocolError):
                asyncio.run(executor.dispatch({**request, "user_id": "9"}, 101))
            with self.assertRaises(ConfigurationError):
                asyncio.run(executor.dispatch({"op": "create", "action": "body_capture_exclusions",
                    "profile": "body_capture_exclusions", "reason": "test", "requested_by_uid": 102}, 101))
            row = store.get(created["id"])
            asyncio.run(executor.dispatch({"op": "posted", "request_id": row["id"],
                                            "message_id": "44"}, 101))
            decision = {"op": "decide", "request_id": row["id"], "decision": "approve",
                "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
                "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
                "interaction_id": "55"}
            completed = asyncio.run(executor.dispatch(decision, 101))["request"]
            self.assertEqual(completed["status"], "completed")
            self.assertIn("discordcdn.com", self.path.read_text())
            events = [json.loads(line) for line in (self.base / "audit.jsonl").read_text().splitlines()]
            self.assertTrue(any(event["event"] == "request_created" and
                                event["requested_by_discord_id"] == "1" for event in events))
            self.assertTrue(any(event["event"] == "configuration_applied" and
                                event["resulting_hosts"] == ["discord.com", "discordcdn.com"]
                                for event in events))
            self.assertTrue(any(event["event"] == "approval_granted" and
                                event["resulting_hosts"] == ["discord.com", "discordcdn.com"]
                                for event in events))
            with self.assertRaises(StateError):
                asyncio.run(executor.dispatch(decision, 101))
        finally:
            store.close()

    def test_changed_file_before_approval_is_failed_and_audited(self) -> None:
        store = Store(self.base / "state.db", self.base / "audit.jsonl")
        lookup = lambda name: SimpleNamespace(pw_uid=101 if name == "deadbolt" else 102,
                                              pw_gid=201 if name == "deadbolt" else 202)
        try:
            with patch("deadbolt.executor.pwd.getpwnam", side_effect=lookup):
                executor = Executor(config(self.base), policy(), store, clock=lambda: 1000.0,
                                    policy_loader=policy, exclusions_action=self.action)
            created = asyncio.run(executor.dispatch({"op": "exclusion_create", "operation": "add",
                "hostname": "discordcdn.com", "user_id": "1", "guild_id": "2",
                "channel_id": "3", "interaction_id": "54"}, 101))["request"]
            row = store.get(created["id"])
            asyncio.run(executor.dispatch({"op": "posted", "request_id": row["id"],
                                           "message_id": "44"}, 101))
            self.path.write_text("# changed\ndiscord.com\n")
            failed = asyncio.run(executor.dispatch({"op": "decide", "request_id": row["id"],
                "decision": "approve", "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
                "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
                "interaction_id": "55"}, 101))["request"]
            self.assertEqual(failed["status"], "failed")
            self.assertIn("# changed", self.path.read_text())
            events = [json.loads(line) for line in (self.base / "audit.jsonl").read_text().splitlines()]
            self.assertTrue(any(event["event"] == "execution_failed" and
                                event["requested_hosts"] == ["discord.com", "discordcdn.com"]
                                for event in events))
        finally:
            store.close()

    def test_exclusion_restart_recovers_committed_replacement(self) -> None:
        store = Store(self.base / "state.db", self.base / "audit.jsonl")
        lookup = lambda name: SimpleNamespace(pw_uid=101 if name == "deadbolt" else 102,
                                              pw_gid=201 if name == "deadbolt" else 202)
        try:
            with patch("deadbolt.executor.pwd.getpwnam", side_effect=lookup):
                executor = Executor(config(self.base), policy(), store, clock=lambda: 1000.0,
                                    policy_loader=policy, exclusions_action=self.action)
            canonical = self.action.create_change("remove", "discord.com",
                                                  policy().body_exclusion_allowed_hosts)
            row = store.create(canonical, "exclusion card", 102, 1000)
            store.mark_posted(row["id"], "44", 1000)
            store.decide(row["id"], "approve", row["nonce"], row["canonical_hash"],
                         "1", "2", "3", "44", "55", ("1", "2", "3"), 1000)
            intent = self.action.prepare(canonical)
            store.mark_executing(row["id"], intent, 1000)
            self.action.apply(canonical, intent)
            asyncio.run(executor.reconcile())
            self.assertEqual(store.get(row["id"])["status"], "completed")
            self.assertEqual(self.path.read_text(), intent["after"])
        finally:
            store.close()


class IngressTests(unittest.TestCase):
    def test_hermes_cannot_call_operator_operations(self) -> None:
        config = BotConfig(Path("/tmp/ingress"), Path("/tmp/root"), "hermes", "1", "2", "3", None, True)
        with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=102)):
            relay = Relay(config)
        for operation in ("capture_status", "capture_disable", "exclusion_create",
                          "emergency_stop", "emergency_status", "emergency_recover_create"):
            with self.assertRaises(ProtocolError):
                asyncio.run(relay.submit({"op": operation, "action": "proxy_body_capture",
                                          "profile": "proxy_body_capture", "reason": "test"}, 102))
