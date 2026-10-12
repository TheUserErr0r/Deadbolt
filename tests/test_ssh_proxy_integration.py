"""Optional isolated SSH-MITM wire test; no production target or firewall changes."""

import base64
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _target(port, host_key, allowed_key):
    import paramiko

    class Target(paramiko.ServerInterface):
        command = None
        shell = False

        def get_allowed_auths(self, username):
            return "publickey"

        def check_auth_publickey(self, username, key):
            return (paramiko.AUTH_SUCCESSFUL if username == "reptor" and
                    key.get_base64() == allowed_key else paramiko.AUTH_FAILED)

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            self.command = command
            return True

        def check_channel_pty_request(self, *args):
            return True

        def check_channel_shell_request(self, channel):
            self.shell = True
            return True

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(5)
    while True:
        peer, _ = listener.accept()
        transport = paramiko.Transport(peer)
        transport.add_server_key(paramiko.Ed25519Key.from_private_key_file(host_key))
        interface = Target()
        try:
            transport.start_server(server=interface)
            channel = transport.accept(10)
            if channel:
                for _ in range(100):
                    if interface.command or interface.shell:
                        break
                    time.sleep(0.01)
                if interface.command == b"id":
                    channel.sendall(b"uid=1000(reptor)\n")
                    channel.send_stderr(b"warning: mock\n")
                    channel.send_exit_status(0)
                elif interface.shell:
                    data = channel.recv(1024)
                    if data == b"cat /etc/os-release\n":
                        channel.sendall(b"ID=test\n")
                channel.close()
        finally:
            transport.close()


def _proxy(lease):
    from deadbolt.ssh_proxy import build_server
    # The disposable wire fixture cannot create root-owned policy files.
    # Production ownership checks are separately exercised in unit tests.
    with patch("deadbolt.ssh_proxy.read_lease", return_value=lease), patch(
        "deadbolt.ssh_proxy._public_key_line",
        return_value=tuple(Path(lease["hermes_client_key"]).read_text().split()[:2])):
        build_server().start()


@unittest.skipUnless(os.environ.get("DEADBOLT_SSH_PROXY_INTEGRATION") == "1",
                     "set DEADBOLT_SSH_PROXY_INTEGRATION=1 with SSH-MITM 6.0.0 installed")
class SSHProxyWireTest(unittest.TestCase):
    def test_fixed_upstream_key_and_transcript(self):
        import paramiko
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spool = root / "spool"
            spool.mkdir(mode=0o700)

            def key(name):
                path = root / name
                path.write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(
                    Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
                path.chmod(0o600)
                return path, paramiko.Ed25519Key.from_private_key_file(str(path))

            target_path, target_key = key("target")
            proxy_path, proxy_key = key("proxy")
            upstream_path, upstream_key = key("upstream")
            client_path, client_key = key("client")
            client_pub = root / "client.pub"
            client_pub.write_text(f"ssh-ed25519 {client_key.get_base64()}\n")
            client_pub.chmod(0o644)
            target_port, proxy_port = _free_port(), _free_port()
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(target_key.asbytes()).digest()).decode().rstrip("=")
            lease = {"request_id": str(uuid.uuid4()), "expires_at": int(time.time()) + 60,
                     "destination": "127.0.0.1", "port": target_port, "ssh_user": "reptor",
                     "ssh_key": str(upstream_path), "target_host_fingerprint": fingerprint,
                     "proxy_port": proxy_port, "proxy_host_key": str(proxy_path),
                     "hermes_client_key": str(client_pub), "spool_dir": str(spool)}
            target = multiprocessing.Process(target=_target, args=(target_port, str(target_path), upstream_key.get_base64()), daemon=True)
            proxy = multiprocessing.Process(target=_proxy, args=(lease,), daemon=True)
            target.start()
            proxy.start()
            try:
                time.sleep(0.8)
                client = paramiko.SSHClient()
                client.get_host_keys().add("[127.0.0.1]:" + str(proxy_port), "ssh-ed25519", proxy_key)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.connect("127.0.0.1", port=proxy_port, username="hermes", pkey=client_key,
                               allow_agent=False, look_for_keys=False, timeout=5, auth_timeout=5)
                _, stdout, stderr = client.exec_command("id", timeout=5)
                self.assertEqual(stdout.read(), b"uid=1000(reptor)\n")
                self.assertEqual(stderr.read(), b"warning: mock\n")
                client.close()
                client.connect("127.0.0.1", port=proxy_port, username="hermes", pkey=client_key,
                               allow_agent=False, look_for_keys=False, timeout=5, auth_timeout=5)
                channel = client.invoke_shell()
                channel.sendall(b"cat /etc/os-release\n")
                self.assertEqual(channel.recv(1024), b"ID=test\n")
                channel.close()
                client.close()
                for _ in range(30):
                    manifests = list(spool.glob("*/manifest.json"))
                    if len(manifests) >= 2:
                        break
                    time.sleep(0.1)
                self.assertEqual(len(manifests), 2)
                evidence = []
                for manifest in manifests:
                    frames = [json.loads(line) for line in (manifest.parent / "frames.jsonl").read_text().splitlines()]
                    evidence.extend((f["event"], base64.b64decode(f["data_b64"])) for f in frames)
                for expected in (("exec_request", b"id"), ("stdout", b"uid=1000(reptor)\n"),
                                 ("stderr", b"warning: mock\n"),
                                 ("stdin", b"cat /etc/os-release\n"), ("stdout", b"ID=test\n")):
                    self.assertIn(expected, evidence)
            finally:
                proxy.terminate()
                target.terminate()
                proxy.join(5)
                target.join(5)
