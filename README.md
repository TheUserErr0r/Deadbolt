# Deadbolt

Human-approved, time-limited privileged actions for AI agents.

Deadbolt v0.5 is an **undeployed local development release**. It accepts a small structured request from an unprivileged `hermes` user, relays it through a dedicated `deadbolt` Discord bot account, and lets a root executor apply only root-owned UFW profiles after a configured human approves. No generic command, destination, port, service name, or systemd unit can be supplied by Hermes. The repository deliberately contains no deployment credentials or real profiles.

## Architecture

```text
hermes -- /run/deadbolt/ingress/hermes.sock --> deadbolt bot (no sudo)
                                              |
                                              | /run/deadbolt/bot.sock
                                              v
                                         root executor --> UFW
                                              |
                                         SQLite + JSONL audit
```

The bot verifies the Hermes UID using Linux `SO_PEERCRED`. The root executor verifies the `deadbolt` UID in the same way. The root executor creates the immutable approval card and binds its SHA-256 hash to a request ID and one-time nonce. See [architecture](docs/architecture.md) and [security model](SECURITY.md).

## Local verification

Requires Python 3.12 or newer. The executor uses only the Python standard library. The live bot needs `discord.py`; the unit tests and dry-run relay do not.

For an isolated installation, create a Python virtual environment and install `.` for the executor or `.[bot]` for the Discord relay. The package exposes `deadbolt-executor` and `deadbolt-bot` commands.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The tests use temporary SQLite files and a fake UFW runner. They never alter the host firewall or contact Discord. The bot's `--dry-run` option prints approval cards without a token; it does not approve requests or change UFW rules. Running that relay still requires the dedicated Unix accounts and socket directories; use the unit tests for development on an ordinary workstation.

## Request protocol

Each Unix-socket exchange is one newline-terminated JSON object of at most 16 KiB. Every message has `"version":1`. Hermes can only submit this shape to the ingress socket:

```json
{"version":1,"op":"submit","action":"firewall_profile","profile":"approved-profile","reason":"Time-limited access for a named task","ttl_seconds":900}
```

The bot forwards the request to root, including the UID obtained from peer credentials. Root checks the claimed UID, action and profile, resolves fixed UFW fields, clamps TTL, and returns a request ID. The Discord card shows the exact resolved rule, reason, effective TTL, request ID, and approval deadline. Only the configured Discord user in the configured guild and channel can approve or deny. `/deadbolt status <request-id>` and `/deadbolt deny <request-id>` provide fallbacks.

Pending approval expires after 10 minutes. Active TTL starts after successful application, defaults to 30 minutes, and is capped at 60 minutes and by the chosen profile. Expired grants are swept every five seconds; startup reconciliation runs before the executor accepts requests. If rollback fails, the record stays recoverable and the executor retries.

## Deployment templates

Sanitized configuration lives in `examples/`; systemd templates live in `systemd/`. Production configuration belongs only in `/etc/deadbolt/`, with root-owned policy, state, and audit paths. The `deadbolt` account must be a dedicated non-login user with no sudo or privileged supplementary groups. `zeus` remains the human/operator account and is not used by the bot. The root executor is the only privileged process. The ingress directory is `deadbolt:hermes` mode `0750`; its socket is mode `0666` *inside that private directory* and still checks the peer UID. The root socket is `root:deadbolt` mode `0660` under a root-owned runtime directory.

Do not deploy these templates to Hermes until the local tests, review, concrete root-owned UFW profiles, Discord IDs, and service permissions have been checked. Deployment source should be a pinned release under `/opt/deadbolt`, owned by root and not writable by `hermes` or `deadbolt`.

Teleport identity issuance, renewal, and revocation are disabled in v0.5. Service actions have no permitted profiles. Existing Teleport session recording and Argus telemetry are external to Deadbolt; this project does not change them.

## License

Apache-2.0. See [LICENSE](LICENSE).
