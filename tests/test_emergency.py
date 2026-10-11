"""Emergency-stop privilege boundary, nft ownership, approval, and recovery."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deadbolt.actions import ActionError, EmergencyAction
from deadbolt.bot import BotConfig, Relay
from deadbolt.config import ConfigurationError, ExecutorConfig, Policy, normalize_workload_units
from deadbolt.executor import Executor
from deadbolt.protocol import EMERGENCY_RESPONSE_TIMEOUT_SECONDS, ProtocolError
from deadbolt.store import StateError, Store


class FakeHost:
    def __init__(self) -> None:
        self.blocked = False
        self.changed_rule = False
        self.units = {"hermes-tls-proxy.service": True, "hermes-worker.service": True,
                      "deadbolt-bot.service": True, "alloy.service": True}
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail_start = False
        self.broker_uid: int | None = None
        self.broker_installed = False

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
                if self.broker_uid is not None and self.broker_installed:
                    data["nftables"].append({"rule": {
                        "family": "inet", "table": "deadbolt_killswitch", "chain": "output",
                        "expr": [
                            {"match": {"op": "==", "left": {"meta": {"key": "skuid"}},
                                       "right": self.broker_uid}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp",
                                                                               "field": "dport"}},
                                       "right": 22}}, {"drop": None}],
                        "comment": "deadbolt:emergency-broker-ssh"}})
                return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")
            if argv[1:] == ["-f", "-"] and input_text is not None:
                if input_text.startswith("add table inet deadbolt_killswitch\n"):
                    self.blocked = True
                    self.broker_installed = "deadbolt:emergency-broker-ssh" in input_text
                elif input_text.startswith("add rule inet deadbolt_killswitch output meta skuid"):
                    self.broker_installed = "deadbolt:emergency-broker-ssh" in input_text
                elif input_text == "delete table inet deadbolt_killswitch\n":
                    self.blocked = False
                    self.broker_installed = False
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
        config.profiles_path.write_text("[firewall_profiles]\n")
        lookup = lambda name: SimpleNamespace(pw_uid=101 if name == "deadbolt" else 102,
                                              pw_gid=201 if name == "deadbolt" else 202)
        self.patcher = patch("deadbolt.executor.pwd.getpwnam", side_effect=lookup)
        self.patcher.start()
        self.executor = Executor(config, self.policy, self.store, clock=lambda: self.clock,
            policy_loader=lambda: self.policy, emergency_action=EmergencyAction(102, self.host))
        self.operator = {"user_id": "1", "guild_id": "2", "channel_id": "3", "interaction_id": "50"}

    def tearDown(self) -> None:
        self.patcher.stop()
        self.executor.close()
        self.store.close()
        self.temp.cleanup()

    def dispatch(self, op: str, **fields: object) -> dict:
        return asyncio.run(self.executor.dispatch({"op": op, **self.operator, **fields}, 101))

    def test_stop_is_operator_only_idempotent_and_preserves_evidence_services(self) -> None:
        with self.assertRaises(ProtocolError):
            asyncio.run(self.executor.dispatch({"op": "emergency_stop", **self.operator}, 102))
        with self.assertRaises(ProtocolError):
            self.dispatch("emergency_stop", user_id="9")
        with self.assertRaises(ProtocolError):
            self.dispatch("emergency_stop", guild_id="9")
        with self.assertRaises(ProtocolError):
            self.dispatch("emergency_stop", channel_id="9")
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

    def test_slow_stop_returns_verified_state_and_queues_polling(self) -> None:
        self.assertGreaterEqual(EMERGENCY_RESPONSE_TIMEOUT_SECONDS, 70)

        def slow_host(argv: list[str], input_text: str | None) -> subprocess.CompletedProcess[str]:
            if argv[1:] == ["stop", "hermes-tls-proxy.service"]:
                time.sleep(5.2)
            return self.host(argv, input_text)

        self.executor.emergency_action = EmergencyAction(102, slow_host)

        async def exercise() -> None:
            with patch("deadbolt.executor.peer_uid", return_value=101):
                server = await asyncio.start_unix_server(self.executor.connection,
                    str(self.config.bot_socket))
                bot_config = BotConfig(self.base / "ingress.sock", self.config.bot_socket,
                                       "hermes", "1", "2", "3", None, True)
                with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=102)):
                    relay = Relay(bot_config)
                async with server:
                    started = time.monotonic()
                    stop = asyncio.create_task(relay.emergency_operator(
                        "emergency_stop", "50", "1", "2", "3"))
                    await asyncio.sleep(0.2)
                    self.assertFalse(stop.done(), "executor blocked its event loop")
                    self.assertTrue(self.host.blocked)
                    polling = asyncio.create_task(relay.list_all("pending"))
                    result = await asyncio.wait_for(stop, timeout=15)
                    self.assertGreater(time.monotonic() - started, 5)
                    self.assertEqual(result["state"], "active")
                    self.assertTrue(result["egress_block_enforced"])
                    self.assertFalse(self.host.units["hermes-tls-proxy.service"])
                    self.assertFalse(self.host.units["hermes-worker.service"])
                    self.assertEqual(await asyncio.wait_for(polling, timeout=3), [])

        asyncio.run(exercise())

    def test_hung_broker_command_is_preempted_and_egress_revoked(self) -> None:
        from tests.test_access import FakeFirewall, FakeSSH, profile

        class HungSSH(FakeSSH):
            def __init__(self) -> None:
                super().__init__()
                self.started = threading.Event()
                self.released = threading.Event()
                self.cancelled = False

            def execute(self, *args):
                self.started.set()
                if not self.released.wait(20):
                    raise TimeoutError("hung test SSH command")
                return super().execute(*args)

            def cancel(self, request_id, command_index):
                self.cancelled = True
                self.released.set()

        firewall, ssh = FakeFirewall(), HungSSH()
        self.policy = Policy({}, False, (), ("hermes-worker.service",),
                             {"ssh-session": profile()})
        self.executor.policy = self.policy
        self.executor.access_action = firewall
        self.executor.ssh_executor = ssh
        self.host.broker_uid = 104
        self.executor.emergency_action = EmergencyAction(102, self.host, broker_uid=104)

        async def exercise() -> None:
            with patch("deadbolt.executor.peer_uid", return_value=101):
                server = await asyncio.start_unix_server(self.executor.connection,
                    str(self.config.bot_socket))
                bot_config = BotConfig(self.base / "ingress.sock", self.config.bot_socket,
                                       "hermes", "1", "2", "3", None, True)
                with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=102)):
                    relay = Relay(bot_config)
                async with server:
                    created = (await relay.root({"op": "create", "action": "access_grant",
                        "profile": "ssh-session", "destination": "192.168.1.4",
                        "purpose": "maintenance", "reason": "maintenance", "ttl_seconds": 300,
                        "command": ["uptime"], "requested_by_uid": 102}))["request"]
                    await relay.root({"op": "posted", "request_id": created["id"], "message_id": "44"})
                    posted = (await relay.root({"op": "list", "state": "posted", "offset": 0}))["requests"][0]
                    approved = (await relay.root({"op": "decide", "request_id": posted["id"],
                        "decision": "approve", "nonce": posted["nonce"],
                        "canonical_hash": posted["canonical_hash"], "user_id": "1",
                        "guild_id": "2", "channel_id": "3", "message_id": "44",
                        "interaction_id": "55"}, ssh_response=True))["request"]
                    self.assertEqual(approved["status"], "active")
                    self.assertIn(created["id"], firewall.active)
                    command = asyncio.create_task(relay.root({"op": "access_execute",
                        "request_id": created["id"], "requested_by_uid": 102,
                        "destination": "192.168.1.4", "argv": ["uptime"]}, ssh_response=True))
                    self.assertTrue(await asyncio.to_thread(ssh.started.wait, 2))
                    started = time.monotonic()
                    result = await asyncio.wait_for(relay.emergency_operator(
                        "emergency_stop", "56", "1", "2", "3"), timeout=3)
                    self.assertLess(time.monotonic() - started, 3)
                    self.assertEqual(result["state"], "active")
                    self.assertTrue(ssh.cancelled)
                    self.assertTrue(self.host.blocked)
                    self.assertIn("meta skuid 104 tcp dport 22 drop", "".join(
                        script or "" for argv, script in self.host.calls if argv[1:] == ["-f", "-"]))
                    self.assertFalse(firewall.active)
                    self.assertEqual(self.store.get(created["id"])["status"], "revoked")
                    with self.assertRaises(ProtocolError):
                        await asyncio.wait_for(command, timeout=3)
                    self.assertTrue(self.host.units["deadbolt-bot.service"])
                    self.assertTrue(self.host.units["alloy.service"])

        asyncio.run(exercise())

    def test_stop_host_timeout_fails_and_preserves_egress_block(self) -> None:
        def timed_out_host(argv: list[str], input_text: str | None) -> subprocess.CompletedProcess[str]:
            if argv[1:] == ["stop", "hermes-tls-proxy.service"]:
                raise subprocess.TimeoutExpired(argv, EmergencyAction.HOST_COMMAND_TIMEOUT_SECONDS)
            return self.host(argv, input_text)

        self.executor.emergency_action = EmergencyAction(102, timed_out_host)
        with self.assertRaises(ActionError):
            self.dispatch("emergency_stop")
        self.assertTrue(self.host.blocked)
        self.assertEqual(self.store.emergency_state()["state"], "stopping")
        self.assertNotIn("emergency_stop_active", (self.base / "audit.jsonl").read_text())
        self.assertIn("emergency_stop_failed", (self.base / "audit.jsonl").read_text())

    def test_failed_stop_rpc_reports_failure_not_success(self) -> None:
        def timed_out_host(argv: list[str], input_text: str | None) -> subprocess.CompletedProcess[str]:
            if argv[1:] == ["stop", "hermes-tls-proxy.service"]:
                raise subprocess.TimeoutExpired(argv, EmergencyAction.HOST_COMMAND_TIMEOUT_SECONDS)
            return self.host(argv, input_text)

        self.executor.emergency_action = EmergencyAction(102, timed_out_host)

        async def exercise() -> None:
            with patch("deadbolt.executor.peer_uid", return_value=101):
                server = await asyncio.start_unix_server(self.executor.connection,
                    str(self.config.bot_socket))
                bot_config = BotConfig(self.base / "ingress.sock", self.config.bot_socket,
                                       "hermes", "1", "2", "3", None, True)
                with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=102)):
                    relay = Relay(bot_config)
                async with server:
                    with self.assertRaisesRegex(ProtocolError, "emergency host command failed"):
                        await relay.emergency_operator("emergency_stop", "50", "1", "2", "3")

        asyncio.run(exercise())
        self.assertTrue(self.host.blocked)
        self.assertEqual(self.store.emergency_state()["state"], "stopping")

    def test_emergency_host_process_timeout_is_sixty_seconds(self) -> None:
        with patch("deadbolt.actions.subprocess.run", side_effect=subprocess.TimeoutExpired([], 60)) as run:
            with self.assertRaises(ActionError):
                EmergencyAction(102)._call(["/usr/bin/systemctl", "stop", "hermes-tls-proxy.service"])
            self.assertEqual(run.call_args.kwargs["timeout"], 60)

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

    def test_existing_emergency_table_gains_broker_block(self) -> None:
        self.dispatch("emergency_stop")
        self.host.broker_uid = 104
        action = EmergencyAction(102, self.host, broker_uid=104)
        self.assertFalse(action.enabled())
        action.install_block()
        self.assertTrue(action.enabled())
        self.assertTrue(self.host.broker_installed)

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
        from tests.test_access import profile
        self.dispatch("emergency_stop")
        self.host.blocked = False
        self.host.broker_uid = 104
        self.host.units["hermes-tls-proxy.service"] = True
        with (patch("deadbolt.emergency_restore.os.geteuid", return_value=0),
              patch("deadbolt.emergency_restore._secure_root_path"),
              patch("deadbolt.emergency_restore.Policy.load",
                    return_value=Policy({}, access_profiles={"ssh-session": profile()})),
              patch("deadbolt.emergency_restore.pwd.getpwnam",
                    side_effect=lambda name: SimpleNamespace(pw_uid={
                        "hermes": 102, "deadbolt-ssh": 104}[name])),
              patch("deadbolt.emergency_restore.EmergencyAction",
                    side_effect=lambda uid, broker_uid=None:
                        EmergencyAction(uid, self.host, broker_uid=broker_uid))):
            restore(self.config)
        self.assertTrue(self.host.blocked)
        self.assertTrue(EmergencyAction(102, self.host, broker_uid=104).enabled())
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
