"""Approval parsing, exact firewall order, transcript durability and delivery."""

import base64
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import deadbolt.ssh_transcript as transcript_module
from deadbolt.outbound import OutboundError, OutboundPolicy, canonical_outbound, describe_outbound
from deadbolt.outbound_firewall import ExactEgress, OutboundFirewallError
from deadbolt.ssh_transcript import EvidenceError, TranscriptSpool, recover_orphans
from deadbolt.transcript_delivery import ArgusReceiver, DeliveryError, TranscriptExporter, _loki_lines
from deadbolt.config import ExecutorConfig, Policy
from deadbolt.executor import Executor
from deadbolt.store import StateError, Store
from deadbolt.protocol import ProtocolError
from deadbolt.bot import BotConfig, Relay
from deadbolt.ssh_proxy import LeaseError, _public_key_line


def policy():
    return OutboundPolicy.parse({"enabled": True, "max_ttl_seconds": 86400,
        "allowed_cidrs": ["192.168.1.0/24"], "allow_public": False,
        "proxy_port": 10022, "proxy_host_key": "/etc/deadbolt-ssh-proxy/host_ed25519",
        "hermes_client_key": "/etc/deadbolt-ssh-proxy/hermes.pub",
        "spool_dir": "/var/lib/deadbolt-ssh-proxy/ssh-spool",
        "ssh_targets": [{"ip": "192.168.1.205", "port": 22, "user": "reptor",
                         "key": "/etc/deadbolt-ssh-proxy/keys/sysreptor",
                         "host_fingerprint": "SHA256:" + "A" * 43}]})


class PolicyTests(unittest.TestCase):
    def test_explicit_kind_transport_and_hard_ttl(self):
        item = policy()
        ssh = canonical_outbound(item, kind="ssh", destination="192.168.1.205",
            port=22, ttl_seconds=8 * 3600, purpose="SysReptor setup")
        self.assertEqual(ssh["ssh_user"], "reptor")
        self.assertEqual(ssh["transport"], "tcp")
        for args in ({"kind": None}, {"kind": "raw", "transport": None},
                     {"destination": "https://192.168.1.205"}, {"destination": "192.168.1.205/32"},
                     {"destination": "127.0.0.1"}, {"port": "22"}, {"ttl_seconds": 86401},
                     {"kind": "raw", "transport": "tcp", "port": 443},
                     {"purpose": "example.com/path?token=hidden"},
                     {"kind": "ssh", "destination": "192.168.1.206"}):
            values = dict(kind="ssh", destination="192.168.1.205", port=22,
                          ttl_seconds=3600, purpose="maintenance")
            values.update(args)
            with self.subTest(args=args), self.assertRaises(OutboundError):
                canonical_outbound(item, **values)
        raw = canonical_outbound(item, kind="raw", destination="192.168.1.205",
            port=22, ttl_seconds=3600, purpose="break glass", transport="tcp")
        self.assertIn("BYPASSES SSH INSPECTION", describe_outbound(raw))
        self.assertIn("CONTENTS MAY BE INVISIBLE", describe_outbound(raw))

    def test_proxy_rejects_unprivileged_client_key_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "client.pub"
            path.write_text("ssh-ed25519 " + "A" * 44)
            path.chmod(0o644)
            with self.assertRaises(LeaseError):
                _public_key_line(path)


class FirewallTests(unittest.TestCase):
    def test_rule_is_reinserted_before_lan_deny_and_exact(self):
        rid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        state = {"ufw": False, "before": False, "nft": False}
        calls = []
        raw_sets = " ".join(f"set raw_{transport}{family}_{suffix} {{ }}"
                            for family in (4, 6) for transport in ("tcp", "udp")
                            for suffix in ("active", "managed"))
        raw_rules = "\n".join(
            f'meta skuid 1001 {address} daddr . {transport} dport @raw_{transport}{family}_{suffix} '
            f'{verdict} comment "deadbolt-hermes-raw_{transport}{family}-{label}"'
            for family, address in ((4, "ip"), (6, "ip6"))
            for transport in ("tcp", "udp")
            for suffix, verdict, label in (("active", "accept", "allow"),
                                           ("managed", "drop", "deny")))
        guard = ('type filter hook output priority -151; policy accept;\n'
                 f'set raw22_4 {{ }} set raw22_6 {{ }} {raw_sets}\n'
                 f'{raw_rules}\n'
                 'meta skuid 1001 ip daddr @raw22_4 tcp dport 22 accept comment "deadbolt-hermes-raw22-allow4"\n'
                 'meta skuid 1001 ip6 daddr @raw22_6 tcp dport 22 accept comment "deadbolt-hermes-raw22-allow6"\n'
                 'meta skuid 1001 tcp dport 22 drop comment "deadbolt-hermes-ssh-deny"\n'
                 'meta skuid 1002 oifname "lo" accept comment "deadbolt-proxy-loopback"\n'
                 'meta skuid 1002 ip daddr . tcp dport @approved4 accept comment "deadbolt-proxy-allow4"\n'
                 'meta skuid 1002 ip6 daddr . tcp dport @approved6 accept comment "deadbolt-proxy-allow6"\n'
                 'meta skuid 1002 drop comment "deadbolt-proxy-deny"')
        tag = f"deadbolt:{rid}:5000"

        def run(argv, text):
            calls.append(argv[:])
            if argv[:4] == ["/usr/sbin/nft", "-a", "list", "table"]:
                return subprocess.CompletedProcess(argv, 0, guard, "")
            if argv[:3] == ["/usr/sbin/nft", "get", "element"]:
                return subprocess.CompletedProcess(argv, 0 if state["nft"] else 1,
                    f'comment "{tag}"' if state["nft"] else "", "")
            if argv[:3] == ["/usr/sbin/nft", "add", "element"]:
                state["nft"] = True
            if argv[:3] == ["/usr/sbin/nft", "delete", "element"]:
                state["nft"] = False
            if "-C" in argv:
                return subprocess.CompletedProcess(argv, 0 if state["ufw"] else 1, "", "")
            if "-I" in argv:
                state["ufw"] = True
                state["before"] = True
            if "-D" in argv:
                state["ufw"] = False
            if "-S" in argv:
                chain = argv[-1]
                own = f'-A {chain} -d 192.168.1.205 -p tcp --dport 22 -m owner --uid-owner 1002 -m comment --comment {tag} -j ACCEPT'
                deny = f'-A {chain} -d 192.168.0.0/16 -j DROP'
                lines = [own, deny] if state["before"] else [deny, own]
                return subprocess.CompletedProcess(argv, 0, '\n'.join(lines) if state["ufw"] else deny, "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        firewall = ExactEgress(1001, 1002, run)
        grant = firewall.ensure_grant("ssh", "192.168.1.205", 22, "tcp", rid, 5000, 4000)
        self.assertEqual(grant["ip"], "192.168.1.205")
        self.assertTrue(any("-I" in argv and "--uid-owner" in argv and
                            argv[argv.index("--uid-owner") + 1] == "1002" for argv in calls))
        self.assertTrue(all(not ("0.0.0.0/0" in argv) for argv in calls))
        state["before"] = False  # UFW reload moved the deny ahead of our allow.
        firewall.ensure_grant("ssh", "192.168.1.205", 22, "tcp", rid, 5000, 4001)
        self.assertTrue(state["before"])
        firewall.revoke("ssh", "192.168.1.205", 22, "tcp", rid, 5000)
        self.assertFalse(state["nft"])
        self.assertFalse(state["ufw"])

    def test_guard_rejects_external_change(self):
        firewall = ExactEgress(1001, 1002,
            lambda argv, text: subprocess.CompletedProcess(argv, 0, "type filter hook output priority -151; policy accept;", ""))
        with self.assertRaises(OutboundFirewallError):
            firewall.ensure_guard()


class TranscriptTests(unittest.TestCase):
    def test_fsync_precedes_forward_and_manifest_is_byte_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            rid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            item = TranscriptSpool(root, rid, "192.168.1.205", 22, "reptor")
            item.record("exec_request", b"id")
            item.record("stdin", b"password=secret\n")
            item.record("stdout", b"uid=1000(reptor)\n\x00")
            item.record("stderr", b"warning\n")
            manifest = item.finish()
            body = (item.path / "frames.jsonl").read_bytes()
            self.assertEqual(hashlib.sha256(body).hexdigest(), manifest["sha256"])
            self.assertEqual(len(body.splitlines()), manifest["frame_count"])
            frames = [json.loads(line) for line in body.splitlines()]
            self.assertEqual(base64.b64decode(frames[2]["data_b64"]), b"password=secret\n")
            self.assertEqual(base64.b64decode(frames[3]["data_b64"]), b"uid=1000(reptor)\n\x00")
            self.assertEqual(len(_loki_lines(body, manifest)), manifest["frame_count"])

    def test_local_write_failure_refuses_data_and_orphan_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            rid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            item = TranscriptSpool(root, rid, "192.168.1.205", 22, "reptor")
            with patch("deadbolt.ssh_transcript.os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(EvidenceError):
                    item.record("stdout", b"must not be forwarded")
            os.close(item.fd)
            # A hard crash leaves no completed manifest; independent recovery
            # marks the transcript interrupted rather than pretending success.
            recovered = recover_orphans(root)
            self.assertEqual(recovered, 1)
            manifest = json.loads((item.path / "manifest.json").read_text())
            self.assertTrue(manifest["output_incomplete"])

    def test_normal_finish_keeps_writer_lock_until_manifest_is_durable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            item = TranscriptSpool(root, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                                   "192.168.1.205", 22, "reptor")
            real_commit = transcript_module._commit_manifest
            def commit_while_exporter_checks(*args):
                self.assertEqual(recover_orphans(root), 0)
                self.assertFalse((item.path / "manifest.json").exists())
                real_commit(*args)
            with patch("deadbolt.ssh_transcript._commit_manifest",
                       side_effect=commit_while_exporter_checks):
                item.finish()
            manifest = json.loads((item.path / "manifest.json").read_text())
            self.assertEqual(manifest["reason"], "complete")
            self.assertNotIn("output_incomplete", manifest)

    def test_exporter_recovers_crash_and_delivers_without_another_grant(self):
        with tempfile.TemporaryDirectory() as spool_temp, tempfile.TemporaryDirectory() as argus_temp:
            spool = Path(spool_temp)
            argus = Path(argus_temp)
            spool.chmod(0o700)
            argus.chmod(0o700)
            rid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            item = TranscriptSpool(spool, rid, "192.168.1.205", 22, "reptor")
            item.record("stdout", b"crash-visible output\n")
            receiver = ArgusReceiver(argus, "http://127.0.0.1:13100/loki/api/v1/push", "restricted-test")
            exporter = object.__new__(TranscriptExporter)
            exporter.spool = spool
            exporter.proxy_uid = os.geteuid()
            exporter.host = "argus.test"
            exporter.port = 8443
            exporter.context = object()

            class LokiResponse:
                status = 204
                def __enter__(self): return self
                def __exit__(self, *args): return None

            class Connection:
                def __init__(self, *args, **kwargs):
                    self.headers = {}
                    self.data = bytearray()
                def putrequest(self, *args): pass
                def putheader(self, name, value): self.headers[name] = value
                def endheaders(self): pass
                def send(self, data): self.data.extend(data)
                def getresponse(self):
                    manifest = json.loads(base64.b64decode(self.headers["X-Deadbolt-Manifest"]))
                    with patch("deadbolt.transcript_delivery.urllib.request.urlopen",
                               return_value=LokiResponse()):
                        ack = receiver.store(manifest["session_id"], bytes(self.data), manifest)
                    return SimpleNamespace(status=200, read=lambda limit: json.dumps(ack).encode())
                def close(self): pass

            with patch("deadbolt.transcript_delivery.http.client.HTTPSConnection", Connection):
                self.assertEqual(exporter.once(), (0, 0))
                self.assertFalse((item.path / "manifest.json").exists(),
                                 "exporter must not finalize a live writer")
                os.close(item.fd)  # Simulate the proxy process dying without finish().
                self.assertEqual(exporter.once(), (1, 0))
            manifest = json.loads((argus / item.session_id / "manifest.json").read_text())
            self.assertEqual(manifest["reason"], "proxy_crash")
            self.assertTrue(manifest["output_incomplete"])
            frames = [json.loads(line) for line in
                      (argus / item.session_id / "frames.jsonl").read_text().splitlines()]
            self.assertEqual(base64.b64decode(frames[1]["data_b64"]), b"crash-visible output\n")
            self.assertTrue((item.path / "delivered.json").exists())

    def test_partial_crash_frame_is_preserved_in_restricted_argus_evidence(self):
        with tempfile.TemporaryDirectory() as spool_temp, tempfile.TemporaryDirectory() as argus_temp:
            spool = Path(spool_temp)
            argus = Path(argus_temp)
            spool.chmod(0o700)
            argus.chmod(0o700)
            item = TranscriptSpool(spool, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                                   "192.168.1.205", 22, "reptor")
            item.record("stdout", b"complete output")
            tail = b'{"event":"stdout","data_b64":"unfinished'
            os.write(item.fd, tail)
            os.fsync(item.fd)
            os.close(item.fd)
            self.assertEqual(recover_orphans(spool), 1)
            manifest = json.loads((item.path / "manifest.json").read_text())
            self.assertEqual(manifest["reason"], "proxy_crash")
            self.assertTrue(manifest["output_incomplete"])
            self.assertTrue(manifest["partial_frame"])
            body = (item.path / "frames.jsonl").read_bytes()
            self.assertTrue(body.endswith(tail))
            lines = _loki_lines(body, manifest)
            self.assertIn('"event":"recovery_tail"', lines[-1][1])
            self.assertIn("unfinished", lines[-1][1])
            receiver = ArgusReceiver(argus, "http://127.0.0.1:13100/loki/api/v1/push", "restricted-test")
            class LokiResponse:
                status = 204
                def __enter__(self): return self
                def __exit__(self, *args): return None
            with patch("deadbolt.transcript_delivery.urllib.request.urlopen",
                       return_value=LokiResponse()):
                receiver.store(item.session_id, body, manifest)
            self.assertEqual((argus / item.session_id / "frames.jsonl").read_bytes(), body)

    def test_argus_ack_only_after_restricted_loki_accepts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            rid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            with tempfile.TemporaryDirectory() as spool_temp:
                spool = Path(spool_temp)
                spool.chmod(0o700)
                item = TranscriptSpool(spool, rid, "192.168.1.205", 22, "reptor")
                item.record("stdout", b"hello")
                manifest = item.finish()
                body = (item.path / "frames.jsonl").read_bytes()
            receiver = ArgusReceiver(root, "http://127.0.0.1:13100/loki/api/v1/push", "restricted-test")
            with patch("deadbolt.transcript_delivery.urllib.request.urlopen", side_effect=OSError("Loki down")):
                with self.assertRaises(DeliveryError):
                    receiver.store(manifest["session_id"], body, manifest)
            self.assertFalse((root / manifest["session_id"] / "loki-delivered").exists())
            class Response:
                status = 204
                def __enter__(self): return self
                def __exit__(self, *args): return None
            with patch("deadbolt.transcript_delivery.urllib.request.urlopen", return_value=Response()):
                ack = receiver.store(manifest["session_id"], body, manifest)
            self.assertTrue(ack["ack"])
            self.assertTrue((root / manifest["session_id"] / "loki-delivered").exists())

    def test_receiver_rejects_ordinary_loki_and_missing_completion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            with self.assertRaises(DeliveryError):
                ArgusReceiver(root, "http://127.0.0.1:3100/loki/api/v1/push", "ordinary")
            item = TranscriptSpool(root, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                                   "192.168.1.205", 22, "reptor")
            body = (item.path / "frames.jsonl").read_bytes()
            manifest = {"session_id": item.session_id, "request_id": item.request_id,
                        "frame_count": 1, "sha256": hashlib.sha256(body).hexdigest()}
            receiver = ArgusReceiver(root, "http://127.0.0.1:13100/loki/api/v1/push", "restricted-test")
            with self.assertRaises(DeliveryError):
                receiver.store(item.session_id, body, manifest)
            os.close(item.fd)

    def test_exporter_requires_argus_ack_and_rejects_forged_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            item = TranscriptSpool(root, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                                   "192.168.1.205", 22, "reptor")
            manifest = item.finish()
            exporter = object.__new__(TranscriptExporter)
            exporter.spool = root
            exporter.proxy_uid = os.geteuid()
            exporter.host = "argus.test"
            exporter.port = 8443
            exporter.context = object()

            class Connection:
                def __init__(self, *args, **kwargs): pass
                def putrequest(self, *args): pass
                def putheader(self, *args): pass
                def endheaders(self): pass
                def send(self, data): pass
                def getresponse(self):
                    return SimpleNamespace(status=200, read=lambda limit: json.dumps({
                        "session_id": manifest["session_id"], "sha256": manifest["sha256"],
                        "ack": True}).encode())
                def close(self): pass

            with patch("deadbolt.transcript_delivery.http.client.HTTPSConnection", Connection):
                self.assertTrue(exporter.deliver_one(item.path))
            marker = item.path / "delivered.json"
            self.assertTrue(marker.exists())
            marker.unlink()
            marker.write_text(json.dumps({"session_id": item.session_id,
                                          "sha256": manifest["sha256"], "ack": True}))
            marker.chmod(0o600)
            with patch("deadbolt.transcript_delivery.os.geteuid", return_value=0):
                with self.assertRaises(DeliveryError):
                    exporter.deliver_one(item.path)


class FakeOutbound:
    proxy_uid = 1002
    hermes_uid = 1001
    _chain = staticmethod(ExactEgress._chain)
    _validated = staticmethod(ExactEgress._validated)

    def __init__(self):
        self.grants = {}
        self.guard = True

    def ensure_guard(self):
        self.guard = True

    def ensure_grant(self, kind, ip, port, transport, request_id, expiry, now):
        if not self.guard or now >= expiry:
            raise OutboundFirewallError("guard missing or grant expired")
        self.grants[request_id] = (kind, ip, port, transport, expiry)

    def assert_grant(self, kind, ip, port, transport, request_id, expiry):
        if self.grants.get(request_id) != (kind, ip, port, transport, expiry):
            raise OutboundFirewallError("exact rule missing")

    def revoke(self, kind, ip, port, transport, request_id, expiry):
        self.grants.pop(request_id, None)


class FakeProxy:
    def __init__(self):
        self.active = None

    def activate(self, policy, canonical, request_id, expiry):
        self.active = (request_id, expiry)
        return {"proxy_host": "127.0.0.1", "proxy_port": policy.proxy_port}

    def assert_active(self, request_id, expiry):
        if self.active != (request_id, expiry):
            raise RuntimeError("proxy unavailable")

    def revoke(self, request_id):
        if self.active and self.active[0] == request_id:
            self.active = None


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.store = Store(base / "state.db", base / "audit.jsonl")
        self.now = 1000.0
        self.firewall, self.proxy = FakeOutbound(), FakeProxy()
        self.policy = Policy({}, outbound_access=policy())
        self.config = ExecutorConfig(base / "state.db", base / "audit.jsonl", base / "bot.sock",
                                     base / "profiles.toml", "deadbolt", "hermes", "1", "2", "3")
        self.account = patch("deadbolt.executor.pwd.getpwnam", side_effect=lambda name:
            SimpleNamespace(pw_uid={"deadbolt": 101, "hermes": 1001,
                "deadbolt-ssh-proxy": 1002}[name], pw_gid=200))
        self.account.start()
        self.executor = Executor(self.config, self.policy, self.store, clock=lambda: self.now,
            policy_loader=lambda: self.policy, outbound_firewall=self.firewall,
            proxy_manager=self.proxy)

    def tearDown(self):
        self.executor.close()
        self.account.stop()
        self.store.close()
        self.temp.cleanup()

    def call(self, message):
        return asyncio.run(self.executor.dispatch(message, 101))

    def request(self, kind="ssh"):
        data = {"op": "create", "action": "outbound_access", "profile": kind,
                "kind": kind, "destination": "192.168.1.205", "port": 22,
                "purpose": "controlled build", "reason": "controlled build",
                "ttl_seconds": 3600, "requested_by_uid": 1001}
        if kind == "raw":
            data["transport"] = "tcp"
        created = self.call(data)["request"]
        self.call({"op": "posted", "request_id": created["id"], "message_id": "44"})
        return self.call({"op": "list", "state": "posted"})["requests"][0]

    def approve(self, row, **extra):
        return self.call({"op": "decide", "request_id": row["id"], "decision": "approve",
            "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
            "user_id": "1", "guild_id": "2", "channel_id": "3",
            "message_id": "44", "interaction_id": "55", **extra})["request"]

    def test_approval_revoke_and_expiry_are_separate_from_hermes(self):
        row = self.request()
        approved = self.approve(row)
        self.assertEqual(approved["status"], "active", approved)
        self.assertEqual(self.proxy.active[0], row["id"])
        self.assertIn(row["id"], self.firewall.grants)
        with self.assertRaises(ProtocolError):
            self.call({"op": "outbound_revoke", "request_id": row["id"],
                "user_id": "9", "guild_id": "2", "channel_id": "3", "interaction_id": "56"})
        self.firewall.grants.clear()  # Simulate a UFW reload.
        asyncio.run(self.executor.reconcile())
        self.assertIn(row["id"], self.firewall.grants)
        self.now = 4601
        asyncio.run(self.executor.reconcile())
        self.assertFalse(self.firewall.grants)
        self.assertIsNone(self.proxy.active)
        self.assertEqual(self.store.get(row["id"])["status"], "revoked")

    def test_raw_ssh_needs_explicit_confirmation_and_exact_operator(self):
        row = self.request("raw")
        with self.assertRaises(ProtocolError):
            self.approve(row)
        with self.assertRaises(StateError):
            self.call({"op": "decide", "request_id": row["id"], "decision": "approve",
                "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
                "user_id": "9", "guild_id": "2", "channel_id": "3",
                "message_id": "44", "interaction_id": "55", "raw_ssh_confirmed": True})
        self.assertEqual(self.approve(row, raw_ssh_confirmed=True)["status"], "active")
        self.assertIsNone(self.proxy.active)
        self.assertEqual(self.firewall.grants[row["id"]][:4],
                         ("raw", "192.168.1.205", 22, "tcp"))

    def test_policy_change_and_proxy_failure_fail_closed(self):
        row = self.request()
        self.policy = Policy({})
        with self.assertRaises(OutboundError):
            self.approve(row)
        self.assertFalse(self.firewall.grants)
        self.policy = Policy({}, outbound_access=policy())
        row = self.request()
        self.proxy.assert_active = lambda *args: (_ for _ in ()).throw(RuntimeError("proxy down"))
        result = self.approve(row)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.firewall.grants)

    def test_active_grant_is_revoked_when_root_policy_is_removed(self):
        row = self.request()
        self.assertEqual(self.approve(row)["status"], "active")
        self.policy = Policy({})
        asyncio.run(self.executor.reconcile())
        self.assertEqual(self.store.get(row["id"])["status"], "revoked")
        self.assertFalse(self.firewall.grants)
        self.assertIsNone(self.proxy.active)


class RelayInputTests(unittest.IsolatedAsyncioTestCase):
    async def test_hermes_cannot_revoke_or_default_to_raw(self):
        sent = []
        async def root(path, payload, **kwargs):
            sent.append(payload)
            return {"ok": True, "request": {"id": "approved"}}
        with patch("deadbolt.bot.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=1001)):
            relay = Relay(BotConfig(Path("/tmp/ingress.sock"), Path("/tmp/root.sock"),
                                    "hermes", "1", "2", "3", None, True), root_rpc=root)
        base = {"op": "submit", "action": "outbound_access", "kind": "raw",
                "destination": "192.168.1.205", "port": 22,
                "purpose": "maintenance", "ttl_seconds": 3600}
        with self.assertRaises(ProtocolError):
            await relay.submit(base, 1001)
        with self.assertRaises(ProtocolError):
            await relay.submit({"op": "outbound_revoke", "request_id": "x"}, 1001)
        with self.assertRaises(ProtocolError):
            await relay.submit({**base, "transport": "tcp", "extra": "arbitrary"}, 1001)
        self.assertFalse(sent)


if __name__ == "__main__":
    unittest.main()
