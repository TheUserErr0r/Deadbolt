"""Temporary inbound grants: strict scope, approval, recovery and audit."""

import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from deadbolt.access_cli import parser, payload
from deadbolt.bot import BotConfig, Relay
from deadbolt.config import ExecutorConfig, Policy
from deadbolt.executor import Executor
from deadbolt.ingress import IngressError, IngressPolicy, canonical_ingress
from deadbolt.ingress_firewall import IngressFirewall, IngressFirewallError
from deadbolt.store import Store


def policy():
    return IngressPolicy.parse({"enabled": True, "allowed_source_cidrs": ["192.168.1.0/24"]})


def request(**changes):
    item = dict(protocol="tcp", source_ip="192.168.1.205", local_ip="192.168.1.102",
                port_start=6969, port_end=6973, ttl_seconds=900, reason="CTF callback")
    item.update(changes)
    return item


class IngressPolicyTests(unittest.TestCase):
    def test_exact_canonical_scope_and_defaults(self):
        item = canonical_ingress(policy(), **request())
        self.assertEqual(item["source"], "192.168.1.205/32")
        self.assertEqual((item["port_start"], item["port_end"]), (6969, 6973))
        self.assertEqual(item["direction"], "in")
        with self.assertRaises(IngressError):
            canonical_ingress(IngressPolicy(), **request())
        self.assertEqual(policy().max_ttl_seconds, 3600)
        self.assertEqual(policy().max_port_width, 5)

    def test_rejects_broad_or_ambiguous_input(self):
        cases = ({"source_ip": "192.168.1.0/23"}, {"source_ip": "192.168.2.1"},
                 {"source_ip": "192.168.1.205/24"}, {"source_ip": "192.168.1.205;echo"},
                 {"source_ip": "https://192.168.1.205"}, {"source_ip": "127.0.0.1"},
                 {"source_ip": "192.168.1.٢٠٥"}, {"local_ip": "192.168.1.205/32"},
                 {"local_ip": "8.8.8.8"}, {"local_ip": "127.0.0.1"},
                 {"port_start": 6969, "port_end": 6974}, {"port_start": 22, "port_end": 22},
                 {"ttl_seconds": 3601}, {"ttl_seconds": True}, {"protocol": "tcp udp"},
                 {"reason": "https://example.test/?token=secret"})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(IngressError):
                canonical_ingress(policy(), **request(**change))
        with self.assertRaises(IngressError):
            IngressPolicy.parse({"enabled": True, "allowed_source_cidrs": []})

    def test_cli_keeps_outbound_and_ingress_separate(self):
        args = parser().parse_args(["request", "ingress", "--protocol", "tcp",
            "--source-ip", "192.168.1.205", "--local-ip", "192.168.1.102",
            "--port", "6969-6973", "--ttl", "30m", "--reason", "CTF callback"])
        self.assertEqual(payload(args), {"op": "submit", "action": "ingress_access",
            "protocol": "tcp", "source_ip": "192.168.1.205", "local_ip": "192.168.1.102",
            "port_start": 6969, "port_end": 6973, "ttl_seconds": 1800,
            "reason": "CTF callback"})
        raw = parser().parse_args(["request", "raw", "--ip", "192.168.1.205",
            "--port", "6969", "--ttl", "30m", "--reason", "outbound", "--protocol", "tcp"])
        self.assertEqual(payload(raw)["action"], "outbound_access")

    def test_firewall_refuses_non_deny_ufw_baseline(self):
        firewall = IngressFirewall(lambda argv, data: subprocess.CompletedProcess(
            argv, 0, "Status: active\nDefault: allow (incoming)\n", ""))
        with self.assertRaises(IngressFirewallError):
            firewall._ensure_ufw_active()


class FakeIngress:
    _identity = staticmethod(IngressFirewall._identity)

    def __init__(self):
        self.grants = {}
        self.guard = False
        self.local = "192.168.1.102"

    def assert_local_ip(self, local):
        if local != self.local:
            raise IngressFirewallError("local IP unavailable")

    def ensure_guard(self):
        self.guard = True

    def ensure_grant(self, record, request_id, expiry, now):
        self.assert_local_ip(record["local_ip"])
        if now >= expiry:
            raise IngressFirewallError("expired")
        self.guard = True
        self.grants[request_id] = (record.copy(), expiry)

    def assert_grant(self, record, request_id, expiry):
        if not self.guard or self.grants.get(request_id) != (record, expiry):
            raise IngressFirewallError("grant unavailable")

    def revoke(self, record, request_id, expiry):
        self.grants.pop(request_id, None)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.store = Store(base / "state.db", base / "audit.jsonl")
        self.now = 1000.0
        self.firewall = FakeIngress()
        self.policy = Policy({}, ingress_access=policy())
        self.config = ExecutorConfig(base / "state.db", base / "audit.jsonl", base / "bot.sock",
                                     base / "profiles.toml", "deadbolt", "hermes", "1", "2", "3")
        self.account = patch("deadbolt.executor.pwd.getpwnam", side_effect=lambda name:
            SimpleNamespace(pw_uid={"deadbolt": 101, "hermes": 1001}[name], pw_gid=200))
        self.account.start()
        self.executor = Executor(self.config, self.policy, self.store, clock=lambda: self.now,
            policy_loader=lambda: self.policy, ingress_firewall=self.firewall)

    def tearDown(self):
        self.executor.close()
        self.account.stop()
        self.store.close()
        self.temp.cleanup()

    def call(self, data):
        return asyncio.run(self.executor.dispatch(data, 101))

    def created(self, **changes):
        data = {"op": "create", "action": "ingress_access", "profile": "ingress",
                "requested_by_uid": 1001, **request(**changes)}
        created = self.call(data)["request"]
        self.call({"op": "posted", "request_id": created["id"], "message_id": "44"})
        return self.call({"op": "list", "state": "posted"})["requests"][0]

    def approve(self, row):
        return self.call({"op": "decide", "request_id": row["id"], "decision": "approve",
            "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
            "user_id": "1", "guild_id": "2", "channel_id": "3", "message_id": "44",
            "interaction_id": "55"})["request"]

    def test_approval_status_requester_revoke_and_audit(self):
        row = self.created()
        self.assertIn("192.168.1.205/32", row["description"])
        self.assertEqual(self.approve(row)["status"], "active")
        self.assertIn(row["id"], self.firewall.grants)
        grants = self.call({"op": "ingress_status", "requested_by_uid": 1001})["grants"]
        self.assertEqual(grants[0]["source"], "192.168.1.205/32")
        result = self.call({"op": "ingress_revoke", "request_id": row["id"],
                            "requested_by_uid": 1001})
        self.assertEqual(result["request"]["status"], "revoked")
        self.assertFalse(self.firewall.grants)
        self.assertEqual(self.call({"op": "ingress_revoke", "request_id": row["id"],
                                    "requested_by_uid": 1001})["request"]["status"], "revoked")
        events = [json.loads(line) for line in self.store.audit_path.read_text().splitlines()]
        self.assertTrue({"request_created", "grant_active", "ingress_revoked"}.issubset(
            {event["event"] for event in events}))
        active = next(event for event in events if event["event"] == "grant_active")
        self.assertEqual(active["port_end"], 6973)

    def test_expiry_reboot_reconcile_and_policy_change(self):
        row = self.created()
        self.approve(row)
        self.firewall.grants.clear()  # Reboot or firewall reload removed volatile rules.
        asyncio.run(self.executor.reconcile())
        self.assertIn(row["id"], self.firewall.grants)
        self.now = 1901
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "expired")
        self.assertFalse(self.firewall.grants)
        row = self.created()
        self.approve(row)
        self.policy = Policy({})
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "revoked")

    def test_unverified_firewall_fails_without_active_grant(self):
        row = self.created()
        self.firewall.assert_grant = lambda *args: (_ for _ in ()).throw(
            IngressFirewallError("exact grant could not be verified"))
        result = self.approve(row)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.firewall.grants)
        self.assertFalse(self.call({"op": "ingress_status", "requested_by_uid": 1001})["grants"])

    def test_fresh_approval_replaces_identical_scope_with_new_expiry(self):
        first = self.created()
        self.assertEqual(self.approve(first)["status"], "active")
        first_expiry = self.store.get(first["id"])["active_until"]
        self.now = 1100
        second = self.created(ttl_seconds=1800, reason="Continue CTF callback")
        self.assertEqual(self.store.get(first["id"])["status"], "active")
        self.assertEqual(self.approve(second)["status"], "active")
        self.assertEqual(self.store.get(first["id"])["status"], "revoked")
        self.assertEqual(self.store.get(first["id"])["last_error"], "replaced")
        self.assertEqual(list(self.firewall.grants), [second["id"]])
        self.assertEqual(self.store.get(second["id"])["active_until"], 2900)
        self.assertGreater(self.store.get(second["id"])["active_until"], first_expiry)
        events = [json.loads(line) for line in self.store.audit_path.read_text().splitlines()]
        replacement = next(event for event in events if event["event"] == "ingress_revoked")
        self.assertEqual(replacement["replacement_request_id"], second["id"])

    def test_partially_overlapping_scope_still_fails(self):
        first = self.created()
        self.assertEqual(self.approve(first)["status"], "active")
        second = self.created(port_start=6972, port_end=6974)
        self.assertEqual(self.approve(second)["status"], "failed")
        self.assertEqual(list(self.firewall.grants), [first["id"]])

    def test_failed_replacement_does_not_activate_new_grant(self):
        first = self.created()
        self.assertEqual(self.approve(first)["status"], "active")
        second = self.created()
        original_revoke = self.firewall.revoke
        self.firewall.revoke = lambda *args: (_ for _ in ()).throw(
            IngressFirewallError("old grant could not be revoked"))
        self.assertEqual(self.approve(second)["status"], "failed")
        self.assertEqual(self.store.get(first["id"])["status"], "revoking")
        self.assertNotIn(second["id"], self.firewall.grants)
        self.firewall.revoke = original_revoke
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(first["id"])["status"], "revoked")
        self.assertFalse(self.firewall.grants)

    def test_malformed_and_unauthorized_requests(self):
        with self.assertRaises(Exception):
            self.call({"op": "create", "action": "ingress_access", "profile": "ingress",
                       "requested_by_uid": 1001, **request(), "surprise": "allowed?"})
        row = self.created()
        with self.assertRaises(Exception):
            self.call({"op": "decide", "request_id": row["id"], "decision": "approve",
                "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
                "user_id": "9", "guild_id": "2", "channel_id": "3", "message_id": "44",
                "interaction_id": "55"})
        with self.assertRaises(Exception):
            self.call({"op": "ingress_status", "requested_by_uid": 999})
        self.assertFalse(self.firewall.grants)

    def test_emergency_stop_revokes_active_ingress(self):
        row = self.created()
        self.approve(row)
        self.executor.emergency_action = SimpleNamespace(
            install_block=lambda: None, active_units=lambda units: (),
            enforce=lambda units: None)
        result = self.call({"op": "emergency_stop", "user_id": "1", "guild_id": "2",
                            "channel_id": "3", "interaction_id": "56"})
        self.assertTrue(result["ok"])
        self.assertEqual(self.store.get(row["id"])["status"], "revoked")
        self.assertFalse(self.firewall.grants)
        events = [json.loads(line) for line in self.store.audit_path.read_text().splitlines()]
        self.assertTrue(any(event["event"] == "ingress_revoked" and
                            event["reason"] == "emergency_stop" for event in events))


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_hermes_request_is_strict_and_operator_decides(self):
        forwarded = []

        async def root(path, message, **kwargs):
            forwarded.append(message)
            return {"ok": True, "request": {"id": "pending"}}

        with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=1001)):
            relay = Relay(BotConfig(Path("/tmp/ingress.sock"), Path("/tmp/root.sock"),
                                    "hermes", "1", "2", "3", None, True), root_rpc=root)
        message = {"op": "submit", "action": "ingress_access", **request()}
        with self.assertRaises(Exception):
            await relay.submit(message, 999)
        with self.assertRaises(Exception):
            await relay.submit({**message, "arbitrary_rule": "accept all"}, 1001)
        with self.assertRaises(Exception):
            await relay.submit({**message, "source_ip": "https://192.168.1.205"}, 1001)
        result = await relay.submit(message, 1001)
        self.assertEqual(result["request"]["id"], "pending")
        self.assertEqual(forwarded[0]["requested_by_uid"], 1001)
        self.assertEqual(forwarded[0]["action"], "ingress_access")


if __name__ == "__main__":
    unittest.main()
