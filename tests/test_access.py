"""Broker approval, exact firewall, recovery, and audit tests."""
import asyncio
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from deadbolt.access import AccessError, AccessProfile, canonical_access, command_argv, destination
from deadbolt.bot import BotConfig, Relay
from deadbolt.broker_firewall import BrokerFirewall, BrokerFirewallError
from deadbolt.config import ExecutorConfig, Policy
from deadbolt.executor import Executor
from deadbolt.protocol import SSH_RESPONSE_TIMEOUT_SECONDS
from deadbolt.ssh_exec import (CaptureResult, MAX_HERMES_OUTPUT_BYTES, MAX_OUTPUT_BYTES, SystemdSSHExecutor,
                                _capture_run, redact, run_child, _ssh_argv)
from deadbolt.store import StateError, Store


def profile(**overrides):
    raw = dict(direction="out", protocol="tcp", ports=[22], max_ttl_seconds=900,
        target_types=["ip", "dns"], allowed_cidrs=["192.168.1.0/24"],
        allow_public=False, operator_approval=True, audited_execution=True,
        ssh_user="maintainer", ssh_key="/etc/deadbolt/keys/maintainer",
        known_hosts="/etc/deadbolt/known-hosts/managed",
        remote_commands=["uptime", "id"], max_commands=3, audit_output="metadata")
    raw.update(overrides)
    return AccessProfile.from_mapping("ssh-session", raw)


class InputTests(unittest.TestCase):
    def test_strict_destination_command_and_profile(self):
        for value in ("https://example.com", "user@example.com", "example.com/path",
                      "example.com?q=x", "*.example.com", "localhost", "localhost.example",
                      "example.com ", "example.com\n", "ｅxample.com", "xn--abc.example",
                      "192.168.1.1/32", "127.0.0.1", "::1", "010.0.0.1", "example.com;id"):
            with self.subTest(value=value), self.assertRaises(AccessError):
                destination(value)
        self.assertEqual(destination("HOST.Example"), ("host.example", "dns"))
        for command in ("uptime", [], ["sh", "-c", "id"], ["uptime;id"],
                        ["uptime", "password=abc"], ["uptime", "x\ny"],
                        ["FOO=bar", "uptime"], ["uptime", "x" * 257], ["uptime"] * 17):
            with self.subTest(command=command), self.assertRaises(AccessError):
                command_argv(command)
        for override in ({"ports": [443]}, {"audited_execution": False},
                         {"operator_approval": False}, {"max_commands": 0},
                         {"max_command_seconds": 0}, {"max_command_seconds": 901},
                         {"max_command_seconds": 600}):
            with self.subTest(override=override), self.assertRaises(AccessError):
                profile(**override)
        self.assertEqual(profile().max_command_seconds, 60)
        self.assertEqual(profile(max_command_seconds=900, audit_output="full").max_command_seconds, 900)
        self.assertGreaterEqual(SSH_RESPONSE_TIMEOUT_SECONDS, 990)

    def test_dns_boundary_and_mixed_answers(self):
        item = profile()
        result = canonical_access(item, "host.example", "maintenance", 300, ["uptime"],
                                  resolver=lambda _: ["192.168.1.20"])
        self.assertEqual(result["pinned_ips"], ["192.168.1.20"])
        for answers in ([], ["192.168.1.20", "10.0.0.1"], ["127.0.0.1"],
                        ["192.168.1.20", "192.168.1.21"]):
            with self.subTest(answers=answers), self.assertRaises(AccessError):
                canonical_access(item, "host.example", "maintenance", 300, ["uptime"],
                                 resolver=lambda _: answers)


class FakeFirewall:
    uid = 104
    _identity = staticmethod(BrokerFirewall._identity)

    def __init__(self):
        self.active = {}
        self.reinstalls = 0

    def ensure_guard(self):
        pass

    def ensure_grant(self, ip, request_id, expiry, now):
        self.active[request_id] = (ip, expiry)
        self.reinstalls += 1
        return {"expiry": expiry}

    def assert_grant(self, ip, request_id, expiry):
        if self.active.get(request_id) != (ip, expiry):
            raise BrokerFirewallError("exact grant absent")

    def revoke(self, ip, request_id, expiry):
        if request_id in self.active and self.active[request_id] != (ip, expiry):
            raise BrokerFirewallError("grant identity changed")
        self.active.pop(request_id, None)


class FirewallTests(unittest.TestCase):
    def test_exact_uid_rule_reinstall_and_cleanup(self):
        calls = []
        state = {"element": False, "ufw": False}
        rid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        tag = f"deadbolt:{rid}:1300"
        table = ('type filter hook output priority -1; policy accept;\n'
                 'meta skuid 104 ip daddr @approved4 tcp dport 22 accept comment "deadbolt-ssh-allow4"\n'
                 'meta skuid 104 ip6 daddr @approved6 tcp dport 22 accept comment "deadbolt-ssh-allow6"\n'
                 'meta skuid 104 tcp dport 22 drop comment "deadbolt-ssh-deny"')

        def run(argv, input_text):
            calls.append(argv)
            if argv[:3] == ["/usr/sbin/nft", "-a", "list"]:
                return subprocess.CompletedProcess(argv, 0, table, "")
            if argv[:3] == ["/usr/sbin/nft", "get", "element"]:
                return subprocess.CompletedProcess(argv, 0 if state["element"] else 1,
                    f'comment "{tag}"' if state["element"] else "", "")
            if argv[:3] == ["/usr/sbin/nft", "add", "element"]:
                state["element"] = True
            if argv[:3] == ["/usr/sbin/nft", "delete", "element"]:
                state["element"] = False
            if "-S" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if "-C" in argv:
                return subprocess.CompletedProcess(argv, 0 if state["ufw"] else 1, "", "")
            if "-I" in argv:
                state["ufw"] = True
            if "-D" in argv:
                state["ufw"] = False
            return subprocess.CompletedProcess(argv, 0, "", "")

        action = BrokerFirewall(104, run)
        action.ensure_grant("192.168.1.5", rid, 1300, 1000)
        self.assertTrue(state["element"] and state["ufw"])
        added = next(argv for argv in calls if "-I" in argv)
        self.assertIn("--uid-owner", added)
        self.assertIn("192.168.1.5", added)
        self.assertEqual(added[added.index("-I") + 1:added.index("-I") + 3],
                         ["ufw-user-output", "1"])
        state["ufw"] = False
        action.ensure_grant("192.168.1.5", rid, 1300, 1001)
        action.revoke("192.168.1.5", rid, 1300)
        action.revoke("192.168.1.5", rid, 1300)
        self.assertFalse(state["element"] or state["ufw"])

    def test_static_allow_fails_migration(self):
        def run(argv, _):
            return subprocess.CompletedProcess(argv, 0,
                "-A ufw-user-output -d 192.168.1.205/32 -p tcp --dport 22 -j ACCEPT"
                if "-S" in argv else "", "")
        with self.assertRaises(BrokerFirewallError):
            BrokerFirewall(104, run)._check_static_bypass()


class BrokerCancellationTests(unittest.TestCase):
    def test_unit_appears_between_state_reads_and_is_stopped_again(self):
        rid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        calls = []
        def command(argv, **kwargs):
            calls.append(argv)
            if argv[1] == "stop":
                return subprocess.CompletedProcess(argv, 1 if len(calls) == 1 else 0, "", "")
            if "--property=LoadState" in argv:
                return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
            return subprocess.CompletedProcess(argv, 0,
                "inactive\n" if len(calls) == 2 or len(calls) == 5 else "active\n", "")
        launcher = SystemdSSHExecutor()
        with patch("deadbolt.ssh_exec.subprocess.run", side_effect=command):
            launcher.cancel(rid, 1)
        self.assertEqual([call[1] for call in calls],
                         ["stop", "show", "show", "stop", "show"])

    def test_cancel_uses_fixed_unit_and_requires_inactive_state(self):
        rid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        unit = f"deadbolt-ssh-{rid}-1.service"
        calls = []

        def command(argv, **kwargs):
            calls.append(argv)
            value = ("loaded\n" if "--property=LoadState" in argv else
                     "inactive\n" if "show" in argv else "")
            return subprocess.CompletedProcess(argv, 0, value, "")

        launcher = SystemdSSHExecutor()
        with patch("deadbolt.ssh_exec.subprocess.run", side_effect=command):
            launcher.cancel(rid, 1)
        self.assertEqual(calls[0], ["/usr/bin/systemctl", "stop", unit])
        self.assertEqual(calls[1], ["/usr/bin/systemctl", "show",
                                    "--property=ActiveState", "--value", unit])
        self.assertEqual(calls[2], ["/usr/bin/systemctl", "show",
                                    "--property=LoadState", "--value", unit])
        with self.assertRaises(AccessError):
            launcher.cancel("--bad.service", 1)
        with patch("deadbolt.ssh_exec.subprocess.run", side_effect=lambda argv, **kwargs:
                   subprocess.CompletedProcess(argv, 0,
                       "loaded\n" if "--property=LoadState" in argv else "active\n", "")):
            with self.assertRaises(AccessError):
                launcher.cancel(rid, 1)

    def test_cancel_before_transient_unit_exists_prevents_late_launch(self):
        rid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        calls = []
        def missing_unit(argv, **kwargs):
            calls.append(argv)
            if "--property=LoadState" in argv:
                return subprocess.CompletedProcess(argv, 0, "not-found\n", "")
            if "--property=ActiveState" in argv:
                return subprocess.CompletedProcess(argv, 0, "inactive\n", "")
            return subprocess.CompletedProcess(argv, 5, "", "Unit not found")
        canonical = canonical_access(profile(), "192.168.1.4", "maintenance",
                                     300, ["uptime"])
        with tempfile.TemporaryDirectory() as path:
            with patch("deadbolt.ssh_exec.subprocess.run", side_effect=missing_unit), \
                 patch("deadbolt.ssh_exec.pwd.getpwnam",
                       return_value=type("A", (), {"pw_uid": 104, "pw_gid": 104})()), \
                 patch("deadbolt.ssh_exec._safe_root_file"):
                launched = []
                launcher = SystemdSSHExecutor(Path(path),
                    runner=lambda *args: launched.append(args),
                    owner_uid=Path(path).stat().st_uid)
                partial = launcher.cancel(rid, 1)
                self.assertEqual(partial["stdout_b64"], "")
                self.assertEqual(partial["stderr_b64"], "")
                with self.assertRaisesRegex(AccessError, "cancelled"):
                    launcher.execute(canonical, rid, "55", 1, ["uptime"], 1300, 1000)
                self.assertFalse(launched)
                self.assertFalse(list(Path(path).glob("*.json")))
        self.assertTrue(any("--property=LoadState" in call for call in calls))


class FakeSSH:
    def __init__(self):
        self.calls = []

    def execute(self, canonical, request_id, approval_id, index, argv, expiry, now):
        self.calls.append((request_id, index, argv))
        return dict(request_id=request_id, approval_id=approval_id, command_index=index,
            started_at=now, finished_at=now + 1, destination=canonical["destination"],
            pinned_ip=canonical["pinned_ips"][0], ssh_user=canonical["ssh_user"],
            command=argv, exit_code=0, termination="exit", timed_out=False,
            audit_output="metadata", stdout_b64=None, stderr_b64=None,
            stdout_truncated=False, stderr_truncated=False)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.store = Store(base / "state.db", base / "audit.jsonl")
        self.firewall, self.ssh = FakeFirewall(), FakeSSH()
        self.now = 1000.0
        policy = Policy({}, access_profiles={"ssh-session": profile()})
        config = ExecutorConfig(base / "state.db", base / "audit.jsonl", base / "bot.sock",
                                base / "policy.toml", "deadbolt", "hermes", "1", "2", "3")
        self.account = patch("deadbolt.executor.pwd.getpwnam",
            side_effect=lambda name: type("A", (), {"pw_uid":
                {"deadbolt": 101, "hermes": 102, "deadbolt-ssh": 104}[name], "pw_gid": 200})())
        self.account.start()
        self.dns = patch("deadbolt.access.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("192.168.1.4", 0))])
        self.resolver = self.dns.start()
        self.executor = Executor(config, policy, self.store, clock=lambda: self.now,
            policy_loader=lambda: policy, access_action=self.firewall, ssh_executor=self.ssh)

    def tearDown(self):
        self.executor.close()
        self.dns.stop()
        self.account.stop()
        self.store.close()
        self.temp.cleanup()

    def call(self, payload):
        return asyncio.run(self.executor.dispatch(payload, 101))

    def request(self, command=None):
        row = self.call(dict(op="create", action="access_grant", profile="ssh-session",
            destination="host.example", purpose="maintenance", reason="maintenance",
            ttl_seconds=300, command=command or ["uptime"], requested_by_uid=102))["request"]
        self.call(dict(op="posted", request_id=row["id"], message_id="44"))
        return self.call(dict(op="list", state="posted"))["requests"][0]

    def approve(self, row):
        return self.call(dict(op="decide", request_id=row["id"], decision="approve",
            nonce=row["nonce"], canonical_hash=row["canonical_hash"], user_id="1",
            guild_id="2", channel_id="3", message_id="44", interaction_id="55"))["request"]

    def execute(self, row, argv):
        return self.call(dict(op="access_execute", request_id=row["id"],
            destination="host.example", argv=argv, requested_by_uid=102))

    def test_rebinding_rejects_approval(self):
        row = self.request()
        self.resolver.return_value = [(2, 1, 6, "", ("192.168.1.5", 0))]
        with self.assertRaises(StateError):
            self.approve(row)
        self.assertFalse(self.firewall.active)

    def test_rebinding_after_approval_revokes_session(self):
        row = self.request()
        self.approve(row)
        self.resolver.return_value = [(2, 1, 6, "", ("192.168.1.5", 0))]
        with self.assertRaises(StateError):
            self.execute(row, ["uptime"])
        self.assertFalse(self.firewall.active)
        self.assertEqual(self.store.get(row["id"])["status"], "rolled_back")

    def test_multi_command_limit_revoke_and_audit(self):
        row = self.request()
        self.assertEqual(self.approve(row)["status"], "active")
        with self.assertRaises(StateError):
            self.execute(row, ["id"])
        for argv in (["uptime"], ["id"], ["uptime", "-p"]):
            self.assertEqual(self.execute(row, argv)["ssh"]["exit_code"], 0)
        with self.assertRaises(StateError):
            self.execute(row, ["uptime"])
        with self.assertRaises(StateError):
            self.execute(row, ["cat"])
        with self.assertRaises(Exception):
            self.call(dict(op="access_revoke", request_id=row["id"], user_id="9",
                guild_id="2", channel_id="3", interaction_id="56"))
        result = self.call(dict(op="access_revoke", request_id=row["id"], user_id="1",
            guild_id="2", channel_id="3", interaction_id="56"))
        self.assertEqual(result["request"]["status"], "revoked")
        self.assertFalse(self.firewall.active)
        events = [json.loads(line) for line in self.store.audit_path.read_text().splitlines()]
        self.assertEqual(sum(e["event"] == "ssh_execution_finished" for e in events), 3)
        self.assertTrue(all("stdout" not in e for e in events))

    def test_reconcile_restores_then_expires(self):
        row = self.request()
        self.approve(row)
        self.firewall.active.clear()
        asyncio.run(self.executor.reconcile())
        self.assertIn(row["id"], self.firewall.active)
        self.now = 1301
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "rolled_back")
        self.assertFalse(self.firewall.active)

    def test_interrupted_revoke_is_completed_not_regranted(self):
        row = self.request()
        self.approve(row)
        self.store.begin_access_revoke(row["id"], self.now, "1")
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "revoked")
        self.assertFalse(self.firewall.active)

    def test_audit_preflight_failure_closes_grant(self):
        row = self.request()
        self.approve(row)
        with patch.object(self.store, "flush_audit", side_effect=OSError("disk full")):
            with self.assertRaises(Exception):
                self.execute(row, ["uptime"])
        self.assertFalse(self.ssh.calls)
        self.assertFalse(self.firewall.active)

    def _full_evidence_profile(self):
        policy = Policy({}, access_profiles={"ssh-session": profile(audit_output="full")})
        self.executor.policy = policy
        self.executor.policy_loader = lambda: policy
        self.store.restricted_ssh_audit_path = self.store.audit_path.parent / "ssh-evidence.jsonl"

        class FullSSH(FakeSSH):
            def execute(self, canonical, request_id, approval_id, index, argv, expiry, now):
                self.calls.append((request_id, index, argv))
                return dict(request_id=request_id, approval_id=approval_id,
                    command_index=index, started_at=now, finished_at=now + 1,
                    destination=canonical["destination"], pinned_ip=canonical["pinned_ips"][0],
                    ssh_user=canonical["ssh_user"], command=argv, exit_code=0,
                    termination="exit", timed_out=False, audit_output="full",
                    stdout_b64=base64.b64encode(b"stdout-secret").decode(),
                    stderr_b64=base64.b64encode(b"stderr-secret").decode(),
                    stdout_truncated=False, stderr_truncated=False)

        self.ssh = FullSSH()
        self.executor.ssh_executor = self.ssh

    def test_full_output_returns_to_hermes_after_evidence_without_entering_card_or_normal_audit(self):
        self._full_evidence_profile()
        row = self.request(["uptime", "token=argument-secret"])
        self.assertNotIn("argument-secret", row["description"])
        self.approve(row)
        response = self.execute(row, ["uptime", "token=argument-secret"])
        self.assertEqual(response["ssh"]["exit_code"], 0)
        self.assertEqual(base64.b64decode(response["ssh"]["stdout_b64"]), b"stdout-secret")
        self.assertEqual(base64.b64decode(response["ssh"]["stderr_b64"]), b"stderr-secret")
        self.assertEqual(response["ssh"]["output_encoding"], "base64")
        self.assertFalse(response["ssh"]["stdout_truncated"])
        self.assertFalse(response["ssh"]["stderr_truncated"])
        self.assertNotIn("argument-secret", json.dumps(response))
        ordinary = self.store.audit_path.read_text()
        for secret in ("argument-secret", "stdout-secret", "stderr-secret"):
            self.assertNotIn(secret, ordinary)
        restricted = self.store.restricted_ssh_audit_path.read_text()
        self.assertIn("argument-secret", restricted)
        self.assertIn(base64.b64encode(b"stdout-secret").decode(), restricted)
        self.assertIn(base64.b64encode(b"stderr-secret").decode(), restricted)

    def test_full_response_is_bounded_and_marks_return_truncation(self):
        self._full_evidence_profile()
        output = b"X" * MAX_OUTPUT_BYTES
        error = b"Y" * (MAX_HERMES_OUTPUT_BYTES + 1)
        original = self.ssh.execute
        def large_result(*args):
            result = original(*args)
            result["stdout_b64"] = base64.b64encode(output).decode()
            result["stderr_b64"] = base64.b64encode(error).decode()
            return result
        self.ssh.execute = large_result
        row = self.request(["uptime"])
        self.approve(row)
        response = self.execute(row, ["uptime"])
        self.assertEqual(base64.b64decode(response["ssh"]["stdout_b64"]),
                         output[:MAX_HERMES_OUTPUT_BYTES])
        self.assertEqual(base64.b64decode(response["ssh"]["stderr_b64"]),
                         error[:MAX_HERMES_OUTPUT_BYTES])
        self.assertTrue(response["ssh"]["stdout_truncated"])
        self.assertTrue(response["ssh"]["stderr_truncated"])
        self.assertLess(len(json.dumps({"version": 1, **response}).encode()), 16384)
        evidence = (self.store.restricted_ssh_audit_path).read_text()
        self.assertIn(base64.b64encode(output).decode(), evidence)
        self.assertIn(base64.b64encode(error).decode(), evidence)

    def test_full_evidence_preflight_failure_prevents_execution(self):
        self._full_evidence_profile()
        row = self.request(["uptime", "token=argument-secret"])
        self.approve(row)
        with patch.object(self.store, "flush_restricted_audit", side_effect=OSError("disk full")):
            with self.assertRaises(Exception):
                self.execute(row, ["uptime", "token=argument-secret"])
        self.assertFalse(self.ssh.calls)
        self.assertFalse(self.firewall.active)
        self.assertEqual(self.store.get(row["id"])["status"], "rolled_back")

    def test_full_profile_requires_private_restricted_sink(self):
        self._full_evidence_profile()
        self.store.restricted_ssh_audit_path = None
        with self.assertRaises(AccessError):
            self.request(["uptime", "token=argument-secret"])
        self.assertFalse(self.firewall.active)

    def test_full_evidence_completion_failure_revokes_and_marks_for_inspection(self):
        self._full_evidence_profile()
        row = self.request(["uptime", "token=argument-secret"])
        self.approve(row)
        real_flush = self.store.flush_restricted_audit
        calls = 0

        def fail_completion():
            nonlocal calls
            calls += 1
            if calls >= 3:
                raise OSError("restricted disk full")
            return real_flush()

        with patch.object(self.store, "flush_restricted_audit", side_effect=fail_completion):
            with self.assertRaises(Exception):
                self.execute(row, ["uptime", "token=argument-secret"])
        self.assertEqual(len(self.ssh.calls), 1)
        self.assertFalse(self.firewall.active)
        saved = self.store.get(row["id"])
        self.assertEqual(saved["status"], "rolled_back")
        self.assertIn("inspect", saved["last_error"])
        execution = self.store.db.execute("SELECT state FROM access_executions WHERE request_id=?",
                                          (row["id"],)).fetchone()
        self.assertEqual(execution["state"], "failed")

    def test_restart_does_not_regrant_failed_evidence_session(self):
        self._full_evidence_profile()
        row = self.request(["uptime", "token=argument-secret"])
        self.approve(row)
        _, execution_id, _ = self.store.begin_access_execution(
            row["id"], ["uptime", "token=argument-secret"], self.now)
        self.store.fail_access_execution(execution_id, self.now,
            "restricted SSH evidence delivery failed; inspect session")
        self.firewall.active.clear()
        before = self.firewall.reinstalls
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "rolled_back")
        self.assertEqual(self.firewall.reinstalls, before)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_hermes_receives_bounded_full_result_with_long_rpc_deadline(self):
        config = BotConfig(Path("/tmp/hermes.sock"), Path("/tmp/bot.sock"), "hermes",
                           "1", "2", "3", None, True)
        seen = []
        async def root_rpc(path, payload, **kwargs):
            seen.append((payload, kwargs))
            return {"ok": True, "ssh": {"request_id": payload["request_id"],
                "exit_code": 0, "command_index": 1, "finished_at": 1001,
                "output_encoding": "base64", "stdout_b64": base64.b64encode(b"done").decode(),
                "stderr_b64": "", "stdout_truncated": False, "stderr_truncated": False}}
        with patch("deadbolt.bot.pwd.getpwnam",
                   return_value=type("P", (), {"pw_uid": 100})()):
            relay = Relay(config, root_rpc=root_rpc)
        response = await relay.submit({"op": "ssh_execute", "request_id": "approved-id",
            "destination": "192.168.1.4", "argv": ["uptime"]}, 100)
        self.assertEqual(base64.b64decode(response["ssh"]["stdout_b64"]), b"done")
        self.assertEqual(seen[0][0]["op"], "access_execute")
        self.assertEqual(seen[0][1]["response_timeout_seconds"], SSH_RESPONSE_TIMEOUT_SECONDS)

    async def test_hermes_cannot_revoke_or_send_shell_string(self):
        config = BotConfig(Path("/tmp/hermes.sock"), Path("/tmp/bot.sock"), "hermes",
                           "1", "2", "3", None, True)
        with patch("deadbolt.bot.pwd.getpwnam",
                   return_value=type("P", (), {"pw_uid": 100})()):
            relay = Relay(config, root_rpc=self._rpc)
        with self.assertRaises(Exception):
            await relay.submit({"op": "access_revoke", "request_id": "x"}, 100)
        with self.assertRaises(Exception):
            await relay.submit({"op": "submit", "action": "access_grant", "profile": "ssh-session",
                "destination": "192.168.1.4", "purpose": "check", "ttl_seconds": 300,
                "command": "uptime"}, 100)
        with self.assertRaises(Exception):
            await relay.submit({"op": "ssh_execute", "request_id": "x",
                "destination": "192.168.1.4", "argv": ["uptime"]}, 999)

    async def _rpc(self, _path, payload, **kwargs):
        return {"ok": True, "request": payload}


class AuditTests(unittest.TestCase):
    def test_full_argv_and_streams_are_only_in_restricted_file(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            store = Store(root / "state.db", root / "audit.jsonl", 600,
                          root / "restricted.jsonl")
            command = ["uptime", "token=topsecret"]
            canonical = canonical_access(profile(audit_output="full"),
                "192.168.1.4", "maintenance", 300, command)
            row = store.create(canonical, "card", 100, 1000)
            row = store.mark_posted(row["id"], "44", 1001)
            store.decide(row["id"], "approve", row["nonce"], row["canonical_hash"],
                         "1", "2", "3", "44", "55", ("1", "2", "3"), 1002)
            store.mark_executing(row["id"], {"expiry": 1302}, 1002)
            store.mark_active(row["id"], 1002, active_until=1302)
            _, execution_id, _ = store.begin_access_execution(row["id"], command, 1003)
            store.flush_restricted_audit()
            store.finish_access_execution(execution_id, 1004,
                {"request_id": row["id"], "approval_id": "55", "command_index": 1,
                 "destination": "192.168.1.4", "pinned_ip": "192.168.1.4",
                 "ssh_user": "maintainer", "started_at": 1003, "finished_at": 1004,
                 "command": command, "exit_code": 0, "termination": "exit",
                 "timed_out": False, "audit_output": "full",
                 "stdout_b64": base64.b64encode(b"token=stdout-secret").decode(),
                 "stderr_b64": base64.b64encode(b"password=stderr-secret").decode(),
                 "stdout_truncated": True, "stderr_truncated": False})
            store.flush_restricted_audit()
            store.finalize_access_execution(execution_id, 1004)
            store.flush_audit()
            ordinary = (root / "audit.jsonl").read_text()
            restricted = [json.loads(line) for line in (root / "restricted.jsonl").read_text().splitlines()]
            for secret in ("topsecret", "stdout-secret", "stderr-secret"):
                self.assertNotIn(secret, ordinary)
            self.assertEqual(restricted[0]["argv"], command)
            self.assertEqual(restricted[1]["argv"], command)
            self.assertEqual(restricted[1]["execution_id"], execution_id)
            self.assertEqual(base64.b64decode(restricted[1]["stdout_b64"]), b"token=stdout-secret")
            self.assertEqual(base64.b64decode(restricted[1]["stderr_b64"]), b"password=stderr-secret")
            self.assertEqual(restricted[1]["termination"], "exit")
            self.assertTrue(restricted[1]["stdout_truncated"])
            self.assertFalse(restricted[1]["stderr_truncated"])
            store.close()

    def test_redaction_is_best_effort(self):
        self.assertEqual(redact("token=abc https://example.com/key"),
                         "token=[REDACTED] [URL REDACTED]")

    def test_capture_truncation_is_explicit_and_separate(self):
        script = ("import sys; sys.stdout.buffer.write(b'A'*70000); "
                  "sys.stderr.buffer.write(b'B'*70001)")
        result = _capture_run([sys.executable, "-c", script], b"", 5)
        self.assertEqual(len(result.stdout), MAX_OUTPUT_BYTES)
        self.assertEqual(len(result.stderr), MAX_OUTPUT_BYTES)
        self.assertEqual(result.stdout, b"A" * MAX_OUTPUT_BYTES)
        self.assertEqual(result.stderr, b"B" * MAX_OUTPUT_BYTES)
        self.assertTrue(result.stdout_truncated)
        self.assertTrue(result.stderr_truncated)
        self.assertFalse(result.timed_out)

    def test_capture_timeout_reports_partial_bytes(self):
        script = ("import sys,time; sys.stdout.buffer.write(b'before-timeout'); "
                  "sys.stdout.flush(); time.sleep(2)")
        result = _capture_run([sys.executable, "-c", script], b"", 0.1)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stdout, b"before-timeout")
        self.assertEqual(result.stderr, b"")

    def test_full_capture_reports_bounded_progress_before_command_exits(self):
        seen = []
        script = ("import sys,time; "
                  "sys.stdout.buffer.write(b'token=partial'); sys.stdout.flush(); "
                  "sys.stderr.buffer.write(b'password=partial'); sys.stderr.flush(); "
                  "time.sleep(0.3)")
        result = _capture_run([sys.executable, "-c", script], b"", 2,
            lambda stream, data, truncated: seen.append((stream, data, truncated)))
        self.assertEqual(result.stdout, b"token=partial")
        self.assertEqual(result.stderr, b"password=partial")
        self.assertIn(("stdout", b"token=partial", False), seen)
        self.assertIn(("stderr", b"password=partial", False), seen)


class SSHUnitTests(unittest.TestCase):
    def test_cancel_preserves_progress_received_from_full_evidence_child(self):
        rid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        canonical = canonical_access(profile(audit_output="full"), "192.168.1.4",
                                     "maintenance", 300, ["uptime", "token=secret"])
        ready, release = threading.Event(), threading.Event()
        failure = []

        def runner(argv, payload, timeout, maximum, on_stdout):
            for stream, data in (("stdout", b"token=partial"),
                                 ("stderr", b"password=partial")):
                frame = {"type": "progress", "stream": stream,
                         "data_b64": base64.b64encode(data).decode(), "truncated": False}
                on_stdout((json.dumps(frame, separators=(",", ":")) + "\n").encode())
            ready.set()
            self.assertTrue(release.wait(3))
            return 1, "", ""

        def systemctl(argv, **kwargs):
            if argv[1] == "stop":
                release.set()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if "--property=LoadState" in argv:
                return subprocess.CompletedProcess(argv, 0, "loaded\n", "")
            return subprocess.CompletedProcess(argv, 0, "inactive\n", "")

        with tempfile.TemporaryDirectory() as path:
            with patch("deadbolt.ssh_exec.pwd.getpwnam",
                       return_value=type("A", (), {"pw_uid": 104, "pw_gid": 104})()), \
                 patch("deadbolt.ssh_exec._safe_root_file"), \
                 patch("deadbolt.ssh_exec._bounded_run", runner), \
                 patch("deadbolt.ssh_exec.subprocess.run", side_effect=systemctl):
                unit = SystemdSSHExecutor(Path(path), runner=runner,
                                          owner_uid=Path(path).stat().st_uid)
                worker = threading.Thread(target=lambda: self._execute_cancelled(unit,
                    canonical, rid, failure))
                worker.start()
                self.assertTrue(ready.wait(3))
                partial = unit.cancel(rid, 1)
                worker.join(3)
                self.assertFalse(worker.is_alive())
        self.assertEqual(base64.b64decode(partial["stdout_b64"]), b"token=partial")
        self.assertEqual(base64.b64decode(partial["stderr_b64"]), b"password=partial")
        self.assertEqual(len(failure), 1)
        self.assertIsInstance(failure[0], AccessError)

    @staticmethod
    def _execute_cancelled(unit, canonical, rid, failure):
        try:
            unit.execute(canonical, rid, "55", 1, ["uptime", "token=secret"], 1300, 1000)
        except Exception as exc:
            failure.append(exc)

    def test_child_full_mode_preserves_exact_command_and_binary_streams(self):
        record = {"version": 1, "request_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "approval_id": "55", "command_index": 1, "destination": "host.example",
            "pinned_ip": "192.168.1.4", "ssh_user": "maintainer",
            "ssh_key": "/etc/deadbolt/keys/maintainer",
            "known_hosts": "/etc/deadbolt/known-hosts/managed",
            "argv": ["uptime", "token=topsecret"], "audit_output": "full",
            "expires_at": 1300, "timeout_seconds": 60}
        identity = type("Account", (), {"pw_name": "deadbolt-ssh", "pw_uid": 104,
                                        "pw_gid": 104})()
        with (patch("deadbolt.ssh_exec.pwd.getpwuid", return_value=identity),
              patch("deadbolt.ssh_exec.pwd.getpwnam", return_value=identity),
              patch("deadbolt.ssh_exec.os.geteuid", return_value=104),
              patch("deadbolt.ssh_exec._safe_root_file")):
            result = run_child(record, runner=lambda argv, payload, timeout:
                CaptureResult(0, b"\x00token=out", b"password=err\xff", False, True, False),
                now=lambda: 1000)
        self.assertEqual(result["command"], record["argv"])
        self.assertEqual(base64.b64decode(result["stdout_b64"]), b"\x00token=out")
        self.assertEqual(base64.b64decode(result["stderr_b64"]), b"password=err\xff")
        self.assertTrue(result["stderr_truncated"])

    def test_child_allows_profile_bounded_command_over_one_minute(self):
        record = {"version": 1, "request_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "approval_id": "55", "command_index": 1, "destination": "host.example",
            "pinned_ip": "192.168.1.4", "ssh_user": "maintainer",
            "ssh_key": "/etc/deadbolt/keys/maintainer",
            "known_hosts": "/etc/deadbolt/known-hosts/managed",
            "argv": ["uptime"], "audit_output": "full",
            "expires_at": 1900, "timeout_seconds": 600}
        identity = type("Account", (), {"pw_name": "deadbolt-ssh", "pw_uid": 104,
                                        "pw_gid": 104})()
        deadlines = []
        def runner(argv, payload, timeout):
            deadlines.append(timeout)
            return CaptureResult(0, b"installed", b"", False, False, False)
        with (patch("deadbolt.ssh_exec.pwd.getpwuid", return_value=identity),
              patch("deadbolt.ssh_exec.pwd.getpwnam", return_value=identity),
              patch("deadbolt.ssh_exec.os.geteuid", return_value=104),
              patch("deadbolt.ssh_exec._safe_root_file")):
            result = run_child(record, runner=runner, now=lambda: 1000)
        self.assertEqual(deadlines, [600])
        self.assertEqual(base64.b64decode(result["stdout_b64"]), b"installed")

    def test_fixed_receiver_no_tty_or_forwarding(self):
        argv = _ssh_argv({"ssh_user": "maintainer",
            "ssh_key": "/etc/deadbolt/keys/maintainer",
            "known_hosts": "/etc/deadbolt/known-hosts/managed",
            "destination": "host.example", "pinned_ip": "192.168.1.4"})
        self.assertIn("-T", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertEqual(argv[-2:], ["192.168.1.4",
            "/usr/local/libexec/deadbolt-remote-exec"])
        self.assertNotIn("-t", argv)

    def test_root_launcher_uses_broker_unit_and_no_discord_output(self):
        rid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        canonical = canonical_access(profile(), "192.168.1.4", "maintenance",
                                     300, ["uptime"])
        calls = []
        def runner(argv, payload, timeout, max_output):
            calls.append(argv)
            result = dict(request_id=rid, approval_id="55", command_index=1,
                started_at=1000, finished_at=1001, destination="192.168.1.4",
                pinned_ip="192.168.1.4", ssh_user="maintainer",
                command=["uptime"], exit_code=0, termination="exit", timed_out=False,
                audit_output="metadata", stdout_b64=None, stderr_b64=None,
                stdout_truncated=False, stderr_truncated=False)
            return 0, json.dumps(result) + "\n", ""
        with tempfile.TemporaryDirectory() as path:
            with patch("deadbolt.ssh_exec.pwd.getpwnam",
                       return_value=type("A", (), {"pw_uid": 104, "pw_gid": 104})()), \
                 patch("deadbolt.ssh_exec._safe_root_file"):
                unit = SystemdSSHExecutor(Path(path), runner=runner,
                                          owner_uid=Path(path).stat().st_uid)
                result = unit.execute(canonical, rid, "55", 1, ["uptime"], 1300, 1000)
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("--property=User=deadbolt-ssh", calls[0])
        self.assertIn("--property=IPAddressDeny=any", calls[0])
        self.assertIn("--property=IPAddressAllow=192.168.1.4/32", calls[0])
        self.assertIsNone(result["stdout_b64"])

    def test_root_configured_long_foreground_command_remains_monitored(self):
        rid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        canonical = canonical_access(profile(max_command_seconds=600, audit_output="full"),
            "192.168.1.4", "install package", 900, ["uptime"])
        calls = []
        def runner(argv, payload, timeout, maximum):
            calls.append((argv, timeout))
            result = dict(request_id=rid, approval_id="55", command_index=1,
                started_at=1000, finished_at=1001, destination="192.168.1.4",
                pinned_ip="192.168.1.4", ssh_user="maintainer", command=["uptime"],
                exit_code=0, termination="exit", timed_out=False, audit_output="full",
                stdout_b64=base64.b64encode(b"install complete").decode(),
                stderr_b64="", stdout_truncated=False,
                stderr_truncated=False)
            return 0, json.dumps(result) + "\n", ""
        with tempfile.TemporaryDirectory() as path:
            with patch("deadbolt.ssh_exec.pwd.getpwnam",
                       return_value=type("A", (), {"pw_uid": 104, "pw_gid": 104})()), \
                 patch("deadbolt.ssh_exec._safe_root_file"):
                unit = SystemdSSHExecutor(Path(path), runner=runner,
                                          owner_uid=Path(path).stat().st_uid)
                unit.execute(canonical, rid, "55", 1, ["uptime"], 1900, 1000)
        self.assertIn("--property=RuntimeMaxSec=610s", calls[0][0])
        self.assertEqual(calls[0][1], 610)
