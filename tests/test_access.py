"""Broker approval, exact firewall, recovery, and audit tests."""
import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deadbolt.access import AccessError, AccessProfile, canonical_access, command_argv, destination
from deadbolt.bot import BotConfig, Relay
from deadbolt.broker_firewall import BrokerFirewall, BrokerFirewallError
from deadbolt.config import ExecutorConfig, Policy
from deadbolt.executor import Executor
from deadbolt.ssh_exec import SystemdSSHExecutor, redact, _ssh_argv
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
                         {"operator_approval": False}, {"max_commands": 0}):
            with self.subTest(override=override), self.assertRaises(AccessError):
                profile(**override)

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


class FakeSSH:
    def __init__(self):
        self.calls = []

    def execute(self, canonical, request_id, approval_id, index, argv, expiry, now):
        self.calls.append((request_id, index, argv))
        return dict(request_id=request_id, approval_id=approval_id, command_index=index,
            started_at=now, finished_at=now + 1, destination=canonical["destination"],
            pinned_ip=canonical["pinned_ips"][0], ssh_user=canonical["ssh_user"],
            command=argv, exit_code=0, audit_output="metadata", stdout=None, stderr=None)


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

    def request(self):
        row = self.call(dict(op="create", action="access_grant", profile="ssh-session",
            destination="host.example", purpose="maintenance", reason="maintenance",
            ttl_seconds=300, command=["uptime"], requested_by_uid=102))["request"]
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


class RelayTests(unittest.IsolatedAsyncioTestCase):
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
    def test_output_is_only_in_restricted_file(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            store = Store(root / "state.db", root / "audit.jsonl", 600,
                          root / "restricted.jsonl")
            canonical = canonical_access(profile(audit_output="redacted"),
                "192.168.1.4", "maintenance", 300, ["uptime"])
            row = store.create(canonical, "card", 100, 1000)
            row = store.mark_posted(row["id"], "44", 1001)
            store.decide(row["id"], "approve", row["nonce"], row["canonical_hash"],
                         "1", "2", "3", "44", "55", ("1", "2", "3"), 1002)
            store.mark_executing(row["id"], {"expiry": 1302}, 1002)
            store.mark_active(row["id"], 1002, active_until=1302)
            _, execution_id, _ = store.begin_access_execution(row["id"], ["uptime"], 1003)
            store.finish_access_execution(execution_id, 1004,
                {"request_id": row["id"], "exit_code": 0, "audit_output": "redacted",
                 "stdout": "safe output", "stderr": ""})
            store.flush_audit()
            self.assertNotIn("safe output", (root / "audit.jsonl").read_text())
            self.assertIn("safe output", (root / "restricted.jsonl").read_text())
            store.close()

    def test_redaction_is_best_effort(self):
        self.assertEqual(redact("token=abc https://example.com/key"),
                         "token=[REDACTED] [URL REDACTED]")


class SSHUnitTests(unittest.TestCase):
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
                command=["uptime"], exit_code=0, audit_output="metadata",
                stdout=None, stderr=None)
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
        self.assertIsNone(result["stdout"])
