"""Locked-down SSH-MITM 6.0.0 adapter with synchronous evidence hooks.

SSH-MITM and Paramiko provide SSH termination and cryptography. Deadbolt's
plugins enforce the approved lease, fixed client/upstream keys, allowed channel
types, and fsync-before-forward evidence. Importing this module does not start
the proxy or load a downloaded AppImage.
"""

from __future__ import annotations

import argparse
from configparser import ConfigParser
import inspect
import json
import logging
import os
from pathlib import Path
import stat
import threading
import time
from typing import Any
import uuid

from deadbolt.outbound import literal_ip
from deadbolt.proxy_manager import ProxyManager
from deadbolt.ssh_transcript import EvidenceError, TranscriptSpool, recover_orphans


class LeaseError(RuntimeError):
    pass


def read_lease(path: Path = ProxyManager.LEASE, *, expected_id: str | None = None) -> dict[str, Any]:
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o027):
            raise LeaseError("SSH proxy lease has unsafe ownership or mode")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise LeaseError("approved SSH proxy lease is unavailable") from exc
    required = {"request_id", "expires_at", "destination", "port", "ssh_user", "ssh_key",
                "target_host_fingerprint", "proxy_port", "proxy_host_key", "hermes_client_key", "spool_dir"}
    if not isinstance(value, dict) or set(value) != required:
        raise LeaseError("approved SSH proxy lease is invalid")
    try:
        request_id = str(uuid.UUID(value["request_id"]))
        literal_ip(value["destination"])
    except (ValueError, KeyError, TypeError) as exc:
        raise LeaseError("approved SSH proxy lease is invalid") from exc
    if (request_id != value["request_id"] or expected_id is not None and request_id != expected_id
            or type(value["expires_at"]) is not int or time.time() >= value["expires_at"]
            or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
            or type(value["proxy_port"]) is not int or not 1025 <= value["proxy_port"] <= 65535):
        raise LeaseError("SSH proxy grant is revoked or expired")
    return value


def _public_key_line(path: Path) -> tuple[str, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise LeaseError("Hermes client public key is unsafe")
    parts = path.read_text(encoding="ascii").strip().split()
    if len(parts) < 2 or parts[0] not in ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"):
        raise LeaseError("Hermes client public key is invalid")
    return parts[0], parts[1]


def build_server(lease_path: Path = ProxyManager.LEASE):
    """Create a configured SSH-MITM server; start() is called only by main()."""
    import paramiko
    from sshmitm.authentication import AuthenticatorRemote, AuthenticationMethod, RemoteCredentials
    from sshmitm.forwarders.ssh import SSHForwarder
    from sshmitm.forwarders.scp import SCPForwarder
    from sshmitm.interfaces.server import ServerInterface
    from sshmitm.moduleparser.baseparser import BaseModuleArgumentParser
    from sshmitm.server import SSHProxyServer
    from sshmitm.session import Session

    # This adapter uses only root-owned Deadbolt policy. Do not load an
    # SSH-MITM user config; the vendor parser otherwise logs every absent
    # optional setting as an error when instantiated without its CLI.
    vendor_config = ConfigParser()
    vendor_config.add_section("deadbolt")
    BaseModuleArgumentParser.ARGCONF = vendor_config

    lease = read_lease(lease_path)
    request_id = lease["request_id"]
    spool_dir = Path(lease["spool_dir"])
    recover_orphans(spool_dir)
    client_key = _public_key_line(Path(lease["hermes_client_key"]))

    def current() -> dict[str, Any]:
        latest = read_lease(lease_path, expected_id=request_id)
        if latest != lease:
            raise LeaseError("SSH proxy approval changed during session")
        return latest

    def close_transports(session) -> None:
        session.transport.close()
        if session.ssh.client and session.ssh.client.transport:
            session.ssh.client.transport.close()

    class FixedAuthenticator(AuthenticatorRemote):
        def get_preconnect_address(self):
            return lease["destination"], lease["port"]

        def get_remote_host_credentials(self, username, password=None, key=None):
            del username, password, key
            return RemoteCredentials(username=lease["ssh_user"], password=None,
                key=RemoteCredentials.load_private_key(lease["ssh_key"]),
                host=lease["destination"], port=lease["port"])

        def auth_publickey(self, username, host, port, key):
            del username, host, port, key
            current()
            self.args.remote_fingerprints = lease["target_host_fingerprint"]
            creds = self.get_remote_host_credentials(lease["ssh_user"])
            return self.connect(creds.username, creds.host, creds.port,
                                AuthenticationMethod.PUBLICKEY, key=creds.key)

    class RecordedSession(Session):
        deadbolt_spool: TranscriptSpool | None = None
        deadbolt_end_reason = "complete"

        def _preconnect_upstream(self):
            # SSH-MITM normally probes the target before authenticating the
            # client. An unauthenticated local client must not induce target
            # connections, even during an approved grant.
            return None

        def start(self):
            started = super().start()
            if started:
                def watchdog():
                    while self.running:
                        try:
                            current()
                        except LeaseError:
                            self.deadbolt_end_reason = "expired" if time.time() >= lease["expires_at"] else "revoked"
                            close_transports(self)
                            break
                        time.sleep(0.25)
                threading.Thread(target=watchdog, daemon=True).start()
            return started

        def close(self):
            try:
                if self.deadbolt_spool is not None and not self.deadbolt_spool.closed:
                    self.deadbolt_spool.finish(self.deadbolt_end_reason)
            finally:
                super().close()

    class StrictInterface(ServerInterface):
        def __init__(self, session):
            super().__init__(session)
            self.args.enabled_exec_handlers = ["NONE"]

        def get_allowed_auths(self, username):
            del username
            return "publickey"

        def check_auth_none(self, username):
            del username
            return paramiko.common.AUTH_FAILED

        def check_auth_password(self, username, password):
            del username, password
            return paramiko.common.AUTH_FAILED

        def check_auth_interactive(self, username, submethods):
            del username, submethods
            return paramiko.common.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            if username != "hermes" or (key.get_name(), key.get_base64()) != client_key:
                return paramiko.common.AUTH_FAILED
            try:
                current()
                # Paramiko invokes this for key discovery and again when it has
                # verified a signed request. Only the signed request may cause
                # the proxy to authenticate upstream with its isolated key.
                frame = inspect.currentframe()
                signed = bool(frame and frame.f_back and frame.f_back.f_locals.get("sig_attached"))
                if not signed:
                    return paramiko.common.AUTH_SUCCESSFUL
                self.session.deadbolt_spool = TranscriptSpool(spool_dir, request_id,
                    lease["destination"], lease["port"], lease["ssh_user"],
                    session_id=str(self.session.sessionid))
                self.session.auth.username_provided = username
                return self.session.authenticator.authenticate(username, key=None)
            except (LeaseError, EvidenceError, OSError):
                return paramiko.common.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            del chanid
            try:
                current()
            except LeaseError:
                return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            return (paramiko.common.OPEN_SUCCEEDED if kind == "session"
                    else paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

        def check_channel_forward_agent_request(self, channel):
            del channel
            return False

        def check_port_forward_request(self, address, port):
            del address, port
            return False

        def check_channel_direct_tcpip_request(self, chanid, origin, destination):
            del chanid, origin, destination
            return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_x11_request(self, *args):
            del args
            return False

        def check_channel_env_request(self, channel, name, value):
            del channel, name, value
            return False

        def check_channel_subsystem_request(self, channel, name):
            del channel, name
            return False

        def check_channel_shell_request(self, channel):
            try:
                current()
                return super().check_channel_shell_request(channel)
            except LeaseError:
                return False

        def check_channel_exec_request(self, channel, command):
            try:
                current()
                if (not isinstance(command, bytes) or not 1 <= len(command) <= 65536
                        or command.split(None, 1)[0].lower() in {
                            b"scp", b"sftp", b"rsync", b"git-upload-pack", b"git-receive-pack",
                            b"mosh", b"netconf", b"powershell"}):
                    return False
                self.session.deadbolt_spool.record("exec_request", command)
                self.session.scp.requested = True
                self.session.scp.command = command
                self.session.scp_channel = channel
                return True
            except EvidenceError:
                self.session.deadbolt_end_reason = "evidence_failure"
                close_transports(self.session)
                return False
            except (LeaseError, IndexError):
                return False

    def persist(session, event, data):
        try:
            current()
            session.deadbolt_spool.record(event, data)
        except EvidenceError:
            session.deadbolt_end_reason = "evidence_failure"
            close_transports(session)
            raise
        except LeaseError:
            session.deadbolt_end_reason = "expired" if time.time() >= lease["expires_at"] else "revoked"
            close_transports(session)
            raise
        return data

    class RecordedShell(SSHForwarder):
        BUF_LEN = 65536

        def handle_client_data(self, data):
            return persist(self.session, "stdin", data)

        def handle_server_data(self, data):
            return persist(self.session, "stdout", data)

        def handle_server_error(self, data):
            return persist(self.session, "stderr", data)

    class RecordedExec(SCPForwarder):
        BUF_LEN = 65536

        def handle_client_data(self, data):
            return persist(self.session, "stdin", data)

        def handle_server_data(self, data):
            return persist(self.session, "stdout", data)

        def handle_error(self, data):
            return persist(self.session, "stderr", data)

    return SSHProxyServer("127.0.0.1", lease["proxy_port"],
        key_algorithms=["ed25519"], key_file_ed25519=lease["proxy_host_key"],
        ssh_interface=RecordedShell, scp_interface=RecordedExec,
        authentication_interface=StrictInterface, authenticator=FixedAuthenticator,
        session_class=RecordedSession)


def main() -> None:
    parser = argparse.ArgumentParser(description="Deadbolt recorded SSH-MITM proxy")
    parser.add_argument("--lease", type=Path, default=ProxyManager.LEASE)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("SSH proxy must run as deadbolt-ssh-proxy, never root")
    logging.basicConfig(level=logging.WARNING)
    build_server(args.lease).start()
