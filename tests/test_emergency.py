"""Emergency-stop privilege boundary, nft ownership, approval, and recovery."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deadbolt.actions import ActionError, EmergencyAction
from deadbolt.bot import BotConfig, Relay
from deadbolt.config import ConfigurationError, ExecutorConfig, Policy, normalize_workload_units
from deadbolt.executor import Executor
from deadbolt.protocol import ProtocolError
from deadbolt.store import StateError, Store


class FakeHost:
    def __init__(self) -> None:
        self.blocked = False
        self.changed_rule = False
        self.units = {"hermes-tls-proxy.service": True, "hermes-worker.service": True,
                      "deadbolt-bot.service": True, "alloy.service": True}
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail_start = False

    def __call__(self, argv: list[str], input_text: str | None) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv[:], input_text))
        if argv[:1] == ["/usr/sbin/nft"]:
            if argv[1:] == ["-j", "list", "tables", "inet"]:
                objects = [{"metainfo": {"version": "1"}}]
                if self.blocked:
                    objects.append({"table": {"family": "inet", "name": "deadbolt_killswitch"}})
                return subprocess.CompletedProcess(argv, 0, json.dumps({"nftables": objects}), "")
            if argv[1:] == ["-j", "list", "table", "inet", "deadbolt_killswitch"]:
                expression = [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}},
                                         "right": 102}}, {"drop": None}]
                data = {"nftables": [
                    {"table": {"family": "inet", "name": "deadbolt_killswitch"}},
                    {"chain": {"family": "inet", "table": "deadbolt_killswitch", "name": "output",
                               "type": "filter", "hook": "output", "prio": -150, "policy": "accept"}},
                    {"rule": {"family": "inet", "table": "deadbolt_killswitch", "chain": "output",
                              "expr": expression, "comment": "changed" if self.changed_rule else
                              "deadbolt:emergency-stop"}}]}
                return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")
            if argv[1:] == ["-f", "-"] and input_text is not None:
                if input_text.startswith("add table inet deadbolt_killswitch\n"):
                    self.blocked = True
                elif input_text == "delete table inet deadbolt_killswitch\n":
                    self.blocked = False
                else:
                    return subprocess.CompletedProcess(argv, 1, "", "unexpected nft script")
                return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:1] == ["/usr/bin/systemctl"]:
            if argv[1:4] == ["show", "--property=LoadState", "--value"]:
                return subprocess.CompletedProcess(argv, 0,
                    "loaded\n" if argv[4] in self.units else "not-found\n", "")
            if argv[1:4] == ["show", "--property=ActiveState", "--value"]:
                return subprocess.CompletedProcess(argv, 0,
                    "active\n" if self.units.get(argv[4], False) else "inactive\n", "")
            if argv[1] == "stop":
                self.units[argv[2]] = False
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[1] == "start":
                if self.fail_start:
                    return subprocess.CompletedProcess(argv, 1, "", "secret service output")
                self.units[argv[2]] = True
                return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 1, "", "unexpected command")


class EmergencyTests(unittest.TestCase):
    def test_policy_rejects_protected_or_unbounded_service_names(self) -> None:
        for units in (["deadbolt-bot.service"], ["deadbolt-executor.service"],
                      ["alloy.service"], ["alloy@collector.service"],
                      ["hermes-tls-proxy.service"], ["../other.service"],
                      ["-bad.service"], ["hermes-worker.service", "hermes-worker.service"]):
            with self.subTest(units=units), self.assertRaises(ConfigurationError):
                normalize_workload_units(units)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.store = Store(self.base / "state.db", self.base / "audit.jsonl")
        self.host = FakeHost()
        self.clock = 1000.0
        self.policy = Policy({}, False, (), ("hermes-worker.service",))
        config = ExecutorConfig(self.base / "state.db", self.base / "audit.jsonl",
            self.base / "bot.sock", self.base / "profiles.toml", "deadbolt", "hermes",
            "1", "2", "3")
        self.config = config
        lookup = lambda name: SimpleNamespace(pw_uid=101 if name == "deadbolt" else 102,
                                              pw_gid=201 if name == "deadbolt" else 202)
        self.patcher = patch("deadbolt.executor.pwd.getpwnam", side_effect=lookup)
        self.patcher.start()
        self.executor = Executor(config, self.policy, self.store, clock=lambda: self.clock,
            policy_loader=lambda: self.policy, emergency_action=EmergencyAction(102, self.host))
        self.operator = {"user_id": "1", "guild_id": "2", "channel_id": "3", "interaction_id": "50"}

    def tearDown(self) -> None:
        self.patcher.stop()
        self.store.close()
        self.temp.cleanup()

    def dispatch(self, op: str, **fields: object) -> dict:
        return asyncio.run(self.executor.dispatch({"op": op, **self.operator, **fields}, 101))

    def test_stop_is_operator_only_idempotent_and_preserves_evidence_services(self) -> None:
        with self.assertRaises(ProtocolError):
            asyncio.run(self.executor.dispatch({"op": "emergency_stop", **self.operator}, 102))
        with self.assertRaises(ProtocolError):
            self.dispatch("emergency_stop", user_id="9")
        result = self.dispatch("emergency_stop")["emergency"]
        self.assertEqual(result["state"], "active")
        self.assertTrue(result["egress_block_enforced"])
        self.assertFalse(self.host.units["hermes-tls-proxy.service"])
        self.assertFalse(self.host.units["hermes-worker.service"])
        self.assertTrue(self.host.units["deadbolt-bot.service"])
        self.assertTrue(self.host.units["alloy.service"])
        self.assertEqual(self.dispatch("emergency_stop")["emergency"]["generation"], 1)
        self.assertEqual(self.dispatch("emergency_status")["emergency"]["state"], "active")
        events = [json.loads(line) for line in (self.base / "audit.jsonl").read_text().splitlines()]
        self.assertIn("emergency_stop_active", [event["event"] for event in events])
        self.assertTrue(any(event["event"] == "emergency_stop_active" and
                            event["approved_by_discord_id"] == "1" for event in events))

    def test_recovery_requires_separate_card_and_new_approval(self) -> None:
        self.dispatch("emergency_stop")
        row = self.dispatch("emergency_recover_create")["request"]
        self.assertIn("restores Hermes network capability", row["description"])
        self.assertTrue(self.host.blocked)
        saved = self.store.get(row["id"])
        asyncio.run(self.executor.dispatch({"op": "posted", "request_id": row["id"],
                                             "message_id": "44"}, 101))
        decision = {"op": "decide", "request_id": row["id"], "decision": "approve",
                    "nonce": saved["nonce"], "canonical_hash": saved["canonical_hash"],
                    "user_id": "1", "guild_id": "2", "channel_id": "3",
                    "message_id": "44", "interaction_id": "55"}
        completed = asyncio.run(self.executor.dispatch(decision, 101))["request"]
        self.assertEqual(completed["status"], "completed")
        self.assertFalse(self.host.blocked)
        self.assertTrue(self.host.units["hermes-tls-proxy.service"])
        self.assertTrue(self.host.units["hermes-worker.service"])
        with self.assertRaises(StateError):
            asyncio.run(self.executor.dispatch(decision, 101))
        self.assertEqual(self.dispatch("emergency_status")["emergency"]["state"], "inactive")

    def test_recovery_failure_reblocks_and_does_not_leak_output(self) -> None:
        self.dispatch("emergency_stop")
        row = self.dispatch("emergency_recover_create")["request"]
        saved = self.store.get(row["id"])
        asyncio.run(self.executor.dispatch({"op": "posted", "request_id": row["id"],
                                             "message_id": "44"}, 101))
        self.host.fail_start = True
        result = asyncio.run(self.executor.dispatch({"op": "decide", "request_id": row["id"],
            "decision": "approve", "nonce": saved["nonce"], "canonical_hash": saved["canonical_hash"],
            "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
            "interaction_id": "55"}, 101))["request"]
        self.assertEqual(result["status"], "failed")
        self.assertTrue(self.host.blocked)
        self.assertEqual(self.store.emergency_state()["state"], "active")
        self.assertNotIn("secret service output", (self.base / "audit.jsonl").read_text())

    def test_external_rule_change_prevents_deletion(self) -> None:
        self.dispatch("emergency_stop")
        self.host.changed_rule = True
        with self.assertRaises(ActionError):
            self.dispatch("emergency_status")
        self.assertTrue(self.host.blocked)
        self.assertFalse(any(text == "delete table inet deadbolt_killswitch\n"
                             for _, text in self.host.calls))

    def test_restart_reenforces_stop_without_auto_recovery(self) -> None:
        self.dispatch("emergency_stop")
        self.host.blocked = False  # nftables runtime rules vanished after reboot.
        self.host.units["hermes-tls-proxy.service"] = True
        asyncio.run(self.executor.reconcile())
        self.assertTrue(self.host.blocked)
        self.assertFalse(self.host.units["hermes-tls-proxy.service"])
        self.assertEqual(self.store.emergency_state()["state"], "active")

    def test_interrupted_recovery_remains_pending_if_reblock_fails(self) -> None:
        self.dispatch("emergency_stop")
        row = self.dispatch("emergency_recover_create")["request"]
        with self.store.db:
            self.store.db.execute("UPDATE requests SET status='approved' WHERE id=?", (row["id"],))
        self.store.mark_executing(row["id"], {"generation": 1}, self.clock)
        self.store.emergency_transition(("active",), "recovering",
            "emergency_recovery_started", self.clock, request_id=row["id"])
        self.host.blocked = False
        with patch.object(self.executor.emergency_action, "enforce",
                          side_effect=ActionError("nft unavailable")):
            asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "executing")
        self.assertEqual(self.store.emergency_state()["state"], "recovering")

    def test_boot_restore_reenforces_before_executor_starts(self) -> None:
        from deadbolt.emergency_restore import restore
        self.dispatch("emergency_stop")
        self.host.blocked = False
        self.host.units["hermes-tls-proxy.service"] = True
        with (patch("deadbolt.emergency_restore.os.geteuid", return_value=0),
              patch("deadbolt.emergency_restore._secure_root_path"),
              patch("deadbolt.emergency_restore.pwd.getpwnam",
                    return_value=SimpleNamespace(pw_uid=102)),
              patch("deadbolt.emergency_restore.EmergencyAction",
                    return_value=EmergencyAction(102, self.host))):
            restore(self.config)
        self.assertTrue(self.host.blocked)
        self.assertFalse(self.host.units["hermes-tls-proxy.service"])
        self.assertIn("emergency_boot_reenforced", (self.base / "audit.jsonl").read_text())

    def test_hermes_ingress_rejects_emergency_operations(self) -> None:
        config = BotConfig(self.base / "ingress.sock", self.base / "bot.sock", "hermes",
                           "1", "2", "3", None, True)
        with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=102)):
            relay = Relay(config)
        for op in ("emergency_stop", "emergency_status", "emergency_recover_create"):
            with self.subTest(op=op), self.assertRaises(ProtocolError):
                asyncio.run(relay.submit({"op": op, "action": "emergency_recover",
                                          "profile": "emergency_recover", "reason": "x"}, 102))


if __name__ == "__main__":
    unittest.main()
