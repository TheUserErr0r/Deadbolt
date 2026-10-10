"""Exercise the shipped systemd units on an ephemeral GitHub-hosted VM.

The bot runs in credential-free dry-run mode. Requests are never approved, so
this test does not call UFW or the body-capture helper.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path("/opt/deadbolt-ci/src")
CLIENT = ("import asyncio,json,sys; from deadbolt.protocol import rpc; "
          "print(json.dumps(asyncio.run(rpc(sys.argv[1],json.loads(sys.argv[2])))))")
INGRESS = Path("/run/deadbolt/ingress")
HERMES_SOCKET = INGRESS / "hermes.sock"
ROOT_SOCKET = Path("/run/deadbolt/bot.sock")


def run(*args: str) -> None:
    subprocess.run(args, check=True, timeout=30)


def wait_for_socket(path: Path) -> None:
    for _ in range(100):
        if path.is_socket():
            return
        time.sleep(0.1)
    raise AssertionError(f"socket did not appear: {path}")


def submit() -> None:
    argv = ["runuser", "-u", "hermes", "--", "/usr/bin/env", f"PYTHONPATH={SOURCE}",
            sys.executable, "-c", CLIENT, str(HERMES_SOCKET), json.dumps({
                "op": "submit", "action": "firewall_profile", "profile": "test-egress",
                "reason": "systemd restart test", "ttl_seconds": 60})]
    for _ in range(50):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            response = json.loads(result.stdout)
            if response["ok"] is True:
                return
            if response.get("error") not in ("[Errno 111] Connection refused",
                                             "[Errno 2] No such file or directory"):
                raise AssertionError(response)
        time.sleep(0.2)
    raise AssertionError(f"Hermes ingress did not recover: {result.stderr or result.stdout}")


def assert_runtime() -> int:
    ingress = INGRESS.stat()
    assert stat.S_IMODE(ingress.st_mode) == 0o750
    assert ingress.st_uid == pwd.getpwnam("deadbolt").pw_uid
    assert ingress.st_gid == pwd.getpwnam("hermes").pw_gid
    root_socket = ROOT_SOCKET.stat()
    assert stat.S_IMODE(root_socket.st_mode) == 0o660
    assert root_socket.st_uid == 0
    assert root_socket.st_gid == pwd.getpwnam("deadbolt").pw_gid
    return ingress.st_ino


def main() -> None:
    assert os.geteuid() == 0
    for user in ("deadbolt", "hermes"):
        run("useradd", "--system", "--user-group", "--no-create-home",
            "--shell", "/usr/sbin/nologin", user)
    config_dir = Path("/etc/deadbolt")
    config_dir.mkdir(mode=0o700)
    config_dir.chmod(0o700)
    Path("/etc/ufw").mkdir(exist_ok=True)
    source_dir = SOURCE.parent
    source_dir.mkdir(mode=0o755)
    shutil.copytree(ROOT / "src", SOURCE)
    profiles = config_dir / "profiles.toml"
    profiles.write_text('[firewall_profiles.test-egress]\n'
                        'direction = "out"\nprotocol = "tcp"\nsource = "any"\n'
                        'destination = "192.0.2.0/24"\nport = 22\nmax_ttl_seconds = 60\n')
    (config_dir / "executor.toml").write_text('''[executor]
state_path = "/var/lib/deadbolt/state.db"
audit_path = "/var/log/deadbolt/audit.jsonl"
bot_socket = "/run/deadbolt/bot.sock"
profiles_path = "/etc/deadbolt/profiles.toml"
bot_user = "deadbolt"
hermes_user = "hermes"

[discord]
user_id = "1"
guild_id = "2"
channel_id = "3"
''')
    (config_dir / "bot.env").write_text('''DEADBOLT_USER_ID=1
DEADBOLT_GUILD_ID=2
DEADBOLT_CHANNEL_ID=3
DEADBOLT_HERMES_SOCKET=/run/deadbolt/ingress/hermes.sock
DEADBOLT_EXECUTOR_SOCKET=/run/deadbolt/bot.sock
''')
    for path in config_dir.iterdir():
        path.chmod(0o600)
    for name in ("deadbolt-executor.service", "deadbolt-bot.service"):
        shutil.copy2(ROOT / "systemd" / name, Path("/run/systemd/system") / name)
    for name, module, extra in (("deadbolt-executor", "deadbolt.executor", "--config /etc/deadbolt/executor.toml"),
                                ("deadbolt-bot", "deadbolt.bot", "--dry-run")):
        override_dir = Path("/run/systemd/system") / f"{name}.service.d"
        override_dir.mkdir()
        (override_dir / "ci.conf").write_text(
            "[Service]\nExecStart=\n"
            f"ExecStart=/usr/bin/env PYTHONPATH={SOURCE} {sys.executable} -m {module} {extra}\n")
    run("systemd-tmpfiles", "--create", str(ROOT / "systemd/deadbolt-tmpfiles.conf"))
    run("systemctl", "daemon-reload")
    try:
        preserve = subprocess.check_output(
            ["systemctl", "show", "deadbolt-executor.service", "-p", "RuntimeDirectoryPreserve"],
            text=True).strip()
        assert preserve == "RuntimeDirectoryPreserve=yes", preserve
        run("systemctl", "start", "deadbolt-executor.service")
        wait_for_socket(ROOT_SOCKET)
        run("systemctl", "start", "deadbolt-bot.service")
        wait_for_socket(HERMES_SOCKET)
        inode = assert_runtime()
        submit()

        run("systemctl", "restart", "deadbolt-executor.service")
        wait_for_socket(ROOT_SOCKET)
        wait_for_socket(HERMES_SOCKET)
        assert assert_runtime() == inode, "executor restart replaced bot ingress directory"
        submit()

        run("systemctl", "restart", "deadbolt-bot.service")
        wait_for_socket(HERMES_SOCKET)
        assert assert_runtime() == inode, "bot restart replaced ingress directory"
        submit()
        print("shipped systemd units preserve ingress and relay requests after both restarts")
    finally:
        subprocess.run(["systemctl", "stop", "deadbolt-bot.service", "deadbolt-executor.service"],
                       check=False, timeout=30)


if __name__ == "__main__":
    main()
