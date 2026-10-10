"""Credential-free integration test of both live Unix sockets and Unix UIDs.

Run only on an ephemeral GitHub-hosted Linux VM as root. The request is denied,
so this test never invokes UFW.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from deadbolt.protocol import rpc

SOURCE = Path(__file__).resolve().parents[2] / "src"
CLIENT = ("import asyncio,json,sys; from deadbolt.protocol import rpc; "
          "print(json.dumps(asyncio.run(rpc(sys.argv[1],json.loads(sys.argv[2])))))")


def as_user(user: str, socket_path: Path, payload: dict[str, object]) -> dict[str, object]:
    result = subprocess.run(
        ["runuser", "-u", user, "--", "/usr/bin/env", f"PYTHONPATH={SOURCE}", sys.executable,
         "-c", CLIENT, str(socket_path), json.dumps(payload)],
        text=True, capture_output=True, timeout=10, check=True)
    return json.loads(result.stdout)


def wait_for_socket(path: Path, process: subprocess.Popen[str]) -> None:
    for _ in range(100):
        if path.is_socket():
            return
        if process.poll() is not None:
            details = process.stderr.read() if process.stderr else ""
            raise AssertionError(f"process exited before {path}: {process.returncode}\n{details}")
        time.sleep(0.1)
    raise AssertionError(f"socket did not appear: {path}")


def main() -> None:
    global SOURCE
    assert os.geteuid() == 0
    for user in ("deadbolt", "hermes"):
        subprocess.run(["useradd", "--system", "--user-group", "--no-create-home",
                        "--shell", "/usr/sbin/nologin", user], check=True)
    bot_gid = pwd.getpwnam("deadbolt").pw_gid
    hermes_gid = pwd.getpwnam("hermes").pw_gid
    processes: list[subprocess.Popen[str]] = []
    runtime = Path(tempfile.mkdtemp(prefix="deadbolt-ci-runtime-"))
    os.chmod(runtime, 0o755)
    try:
        # GitHub checks out source under /home/runner, which service users
        # cannot traverse. Model deployment with a root-owned readable copy.
        shutil.copytree(SOURCE, runtime / "src")
        SOURCE = runtime / "src"
        with tempfile.TemporaryDirectory(prefix="deadbolt-ci-state-") as temp:
            base = Path(temp)
            ingress = runtime / "ingress"
            ingress.mkdir()
            os.chown(ingress, pwd.getpwnam("deadbolt").pw_uid, hermes_gid)
            os.chmod(ingress, 0o750)
            root_socket = runtime / "bot.sock"
            hermes_socket = ingress / "hermes.sock"
            profiles = base / "profiles.toml"
            profiles.write_text('[firewall_profiles.test-egress]\n'
                                'direction = "out"\nprotocol = "tcp"\nsource = "any"\n'
                                'destination = "192.0.2.0/24"\nport = 22\nmax_ttl_seconds = 60\n')
            config = base / "executor.toml"
            config.write_text(f'''[executor]
state_path = "{base / 'state.db'}"
audit_path = "{base / 'audit.jsonl'}"
bot_socket = "{root_socket}"
profiles_path = "{profiles}"
bot_user = "deadbolt"
hermes_user = "hermes"

[discord]
user_id = "1"
guild_id = "2"
channel_id = "3"
''')
            os.chmod(config, 0o600)
            os.chmod(profiles, 0o600)
            environment = {**os.environ, "PYTHONPATH": str(SOURCE)}
            executor = subprocess.Popen(
                [sys.executable, "-m", "deadbolt.executor", "--config", str(config)],
                env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, start_new_session=True)
            processes.append(executor)
            wait_for_socket(root_socket, executor)
            socket_stat = root_socket.stat()
            assert socket_stat.st_uid == 0 and socket_stat.st_gid == bot_gid
            assert stat.S_IMODE(socket_stat.st_mode) == 0o660

            bot_environment = ["/usr/bin/env", f"PYTHONPATH={SOURCE}",
                               f"DEADBOLT_HERMES_SOCKET={hermes_socket}",
                               f"DEADBOLT_EXECUTOR_SOCKET={root_socket}"]
            bot = subprocess.Popen(
                ["runuser", "-u", "deadbolt", "--", *bot_environment,
                 sys.executable, "-m", "deadbolt.bot", "--dry-run"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, start_new_session=True)
            processes.append(bot)
            wait_for_socket(hermes_socket, bot)

            # The intended ingress works; unrelated local users cannot skip a hop.
            created = as_user("hermes", hermes_socket, {
                "op": "submit", "action": "firewall_profile", "profile": "test-egress",
                "reason": "CI socket test", "ttl_seconds": 60})
            assert created["ok"] is True, created
            request_id = created["request"]["id"]
            blocked = subprocess.run(
                ["runuser", "-u", "hermes", "--", "/usr/bin/env", f"PYTHONPATH={SOURCE}",
                 sys.executable, "-c", CLIENT, str(root_socket), json.dumps({"op": "list", "state": "pending"})],
                capture_output=True, text=True, timeout=10)
            assert blocked.returncode != 0 and "PermissionError" in blocked.stderr, blocked.stderr
            root_result = asyncio.run(rpc(str(root_socket), {"op": "list", "state": "pending"}))
            assert root_result == {"version": 1, "ok": False, "error": "unauthorized Unix peer"}, root_result
            ingress_result = asyncio.run(rpc(str(hermes_socket), {"op": "submit"}))
            assert ingress_result == {"version": 1, "ok": False, "error": "unauthorized Unix peer"}, ingress_result

            posted = None
            for _ in range(100):
                rows = as_user("deadbolt", root_socket, {"op": "list", "state": "posted"})["requests"]
                posted = next((row for row in rows if row["id"] == request_id), None)
                if posted:
                    break
                time.sleep(0.1)
            assert posted is not None, "dry-run bot did not post approval"
            denied = as_user("deadbolt", root_socket, {
                "op": "decide", "request_id": request_id, "decision": "deny",
                "nonce": posted["nonce"], "canonical_hash": posted["canonical_hash"],
                "user_id": "1", "guild_id": "2", "channel_id": "3",
                "message_id": posted["posted_message_id"], "interaction_id": "55"})
            assert denied["ok"] is True and denied["request"]["status"] == "denied", denied
            events = [json.loads(line)["event"] for line in (base / "audit.jsonl").read_text().splitlines()]
            assert events == ["request_created", "approval_posted", "approval_denied"], events
            print("live socket peer checks, dry-run relay, denial, and audit passed")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        shutil.rmtree(runtime)


if __name__ == "__main__":
    main()
