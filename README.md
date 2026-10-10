# Deadbolt

[![Deadbolt CI](https://github.com/TheUserErr0r/Deadbolt/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/TheUserErr0r/Deadbolt/actions/workflows/ci.yml)

Human-approved, time-limited privileged actions for AI agents.

Deadbolt v0.6 accepts small structured requests from an unprivileged `hermes` user, relays them through a dedicated `deadbolt` Discord bot account, and lets a root executor apply only root-owned profiles after the configured operator approves. Operator-only commands provide an emergency stop, separately approved recovery, and approved exact-host body-capture exclusions. UFW profiles are supported; body capture remains disabled in the example policy until its helper and independent expiry timer are tested. Hermes cannot supply a command, arbitrary firewall rule, service name, or systemd unit. The repository contains no deployment credentials or real firewall profiles.

## Architecture

```text
hermes -- /run/deadbolt/ingress/hermes.sock --> deadbolt bot (no sudo)
                                              |
                                              | /run/deadbolt/bot.sock
                                              v
                                         root executor --> UFW
                                                       --> fixed body-capture helper
                                                       --> approved exclusion file
                                                       --> dedicated nftables emergency block
                                              |
                                         SQLite + JSONL audit
```

The bot verifies the Hermes UID using Linux `SO_PEERCRED`. The root executor verifies the `deadbolt` UID in the same way. The root executor creates the immutable approval card and binds its SHA-256 hash to a request ID and one-time nonce. See [architecture](docs/architecture.md) and [security model](SECURITY.md).

## Local verification

Requires Python 3.12 or newer. The executor uses only the Python standard library. The live bot needs `discord.py`; the unit tests and dry-run relay do not.

For an isolated installation, create a Python virtual environment and install `.` for the executor or `.[bot]` for the Discord relay. The package exposes `deadbolt-executor`, `deadbolt-emergency-restore`, and `deadbolt-bot` commands.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The local unit tests use temporary SQLite files, fake UFW and nftables runners, and a mocked body-capture helper. They never alter the host firewall or contact Discord. The bot's `--dry-run` option prints approval cards without a token; it does not approve requests or change host policy. Running that relay still requires the dedicated Unix accounts and socket directories.

## GitHub Actions verification

The badge at the top shows the latest **push** result for [Deadbolt CI](.github/workflows/ci.yml). It updates automatically as the workflow runs; click it for job logs and run history. Until `main` has its first run, GitHub displays the latest matching run from another branch.

| Check | What it exercises | Runs on |
| --- | --- | --- |
| Unit | Policy, emergency state and recovery, exclusion matching, mocked Discord approvals, and capture helper | Pull requests and pushes |
| Unix sockets | Real `hermes` and `deadbolt` users, peer credentials, dry-run relay, denial, and audit records | Pushes |
| systemd restarts | Shipped service units, runtime-directory ownership, executor and bot restarts, and Hermes ingress recovery | Pushes and same-repository pull requests |
| Firewall | UFW tagged-rule rollback and a real dedicated nftables kill-switch rule in network-isolated Docker containers | Pushes |

Each job uses a fresh GitHub-hosted runner. No bot token, Discord server, Hermes host, or Argus service is involved.

These checks are useful before lab testing, but they do not establish that a live Discord interaction or the deployed proxy's exclusion behavior works on Hermes. The systemd restart job also runs for pull requests whose head branch belongs to this repository; fork pull requests run the unit suite without executing their code as root.

## How to use it on a controlled test host

Use a disposable or otherwise controlled Linux host for the first end-to-end test. The following describes the intended operator sequence; it does not change Hermes or Argus.

1. Ensure Python 3.12+, UFW, nftables, `systemd`, and the Unix user and group `hermes` exist. Create a separate non-login `deadbolt` service user and group with no sudo or privileged supplementary groups. Leave the interactive `zeus` account alone. Install a pinned Deadbolt checkout or wheel into a root-owned virtual environment at `/opt/deadbolt/venv`; install the `bot` extra there for `discord.py`. Neither `hermes` nor `deadbolt` should be able to edit that environment.
2. Copy `examples/executor.toml`, `examples/profiles.toml`, and `examples/bot.env` into `/etc/deadbolt/` as root-owned files with mode `0600`. Replace every Discord ID and the token in those private copies. Use the same user, guild, and channel IDs in both the executor and bot configurations. Add only reviewed, narrow UFW profiles to `profiles.toml`; the example file permits no action as shipped. Keep all three files out of Git.
3. Install the two Deadbolt service units from `systemd/` under `/etc/systemd/system/`, `systemd/deadbolt-tmpfiles.conf` as `/etc/tmpfiles.d/deadbolt.conf`, and the proxy dependency drop-in as `/etc/systemd/system/hermes-tls-proxy.service.d/deadbolt.conf`. Run `systemd-tmpfiles --create /etc/tmpfiles.d/deadbolt.conf`, then `systemctl daemon-reload`. Start `deadbolt-executor.service` first and `deadbolt-bot.service` second. The executor runs `deadbolt-emergency-restore` before it starts; the drop-in prevents proxy startup if restoration fails. Verify the executor is root, the bot is `deadbolt`, and `/run/deadbolt/bot.sock` is `root:deadbolt` mode `0660`. After either service restarts, verify both sockets and ingress ownership.
4. From a process running **as `hermes`**, submit a named profile. The installed Python package includes a small socket client helper; it adds the protocol version automatically:

   ```sh
   /opt/deadbolt/venv/bin/python - <<'PY'
   import asyncio
   import json
   from deadbolt.protocol import rpc

   result = asyncio.run(rpc("/run/deadbolt/ingress/hermes.sock", {
       "op": "submit",
       "action": "firewall_profile",
       "profile": "https-temporary",  # Must exist in root-owned profiles.toml.
       "reason": "Temporary access for the approved task",
       "ttl_seconds": 900,
   }))
   print(json.dumps(result, indent=2))
   PY
   ```

5. The bot posts the root-generated rule description to the configured Discord channel. Check the profile, network, port, reason, and effective TTL on the card before selecting **Approve** or **Deny**. Only the configured Discord user can decide, and the card expires after ten minutes. `/deadbolt status <request-id>` shows the current state; `/deadbolt deny <request-id>` is available if the card button cannot be used. There is no slash-command approval fallback.
6. On approval, inspect `ufw show added` for the unique `deadbolt:<request-id>` comment and check `/var/log/deadbolt/audit.jsonl` or `journalctl -u deadbolt-executor.service` for the grant event. When the active TTL elapses, the executor should remove only its tagged rule and the request should become `rolled_back`. On denial or pending expiry, UFW should remain unchanged. A rollback failure stays visible in state and audit records for operator attention.

For a token-free relay check, run `deadbolt-bot --dry-run` as the `deadbolt` user while the executor is running, instead of starting the Discord bot service. It prints cards to stdout and cannot approve them. It still requires the same Unix socket directories and root configuration. Never run the bot as `zeus` or root.

Before production use, exercise approval, denial, pending expiry, active expiry, an executor restart with a live grant, and a deliberate rollback failure on the test host. Confirm the actual firewall and Discord results rather than relying only on unit tests.

## Request protocol

Each Unix-socket exchange is one newline-terminated JSON object of at most 16 KiB. Every message has `"version":1`. Hermes can only submit this shape to the ingress socket:

```json
{"version":1,"op":"submit","action":"firewall_profile","profile":"approved-profile","reason":"Time-limited access for a named task","ttl_seconds":900}
```

The bot forwards the request to root, including the UID obtained from peer credentials. Root checks the claimed UID, action and profile, resolves fixed policy fields, and returns a request ID. The Discord card shows the exact resolved action, request ID, and approval deadline. Only the configured Discord user in the configured guild and channel can approve or deny. `/deadbolt status <request-id>` and `/deadbolt deny <request-id>` provide fallbacks.

### Body capture adapter

Install the versioned helper, its **independent** expiry timer, and the rotation templates as described below. Verify the helper against the target proxy before setting `[proxy_body_capture] enabled = true` in root-owned policy. Hermes can then request an approved enable:

```json
{"version":1,"op":"submit","action":"proxy_body_capture","profile":"proxy_body_capture","reason":"diagnostics","hours":2}
```

`hours` must be an integer from 1 through 24. Every enable requires a new Discord approval; the card shows the requested duration and warns that decrypted HTTP request and response bodies are retained on Argus for 24 hours. Deadbolt invokes only `/usr/local/sbin/hermes-body-capture --json enable HOURS`. The helper returns a single compact JSON line with exactly `enabled`, `expires_at` (whole-second RFC3339 UTC or null), and `outcome` (`enabled`, `disabled`, `status`, `expired`, `invalid_ttl`, or `internal_error`). Deadbolt records the helper's expiry, which replaces any prior expiry; it never extends from the old deadline. The helper and its root-owned systemd timer enforce expiry independently of Deadbolt. The helper serializes concurrent calls, and an enabled state with an invalid expiry is disabled by `status` or the timer. Loki retention remains an Argus-side configuration.

Only the configured Discord operator may use `/deadbolt capture_status` and `/deadbolt capture_disable`. These commands call the fixed helper `--json status` and `--json disable` forms without a second approval. Hermes cannot reach them through the ingress socket. The bot and audit log receive only the validated structured result; helper stderr and raw output are discarded. Deadbolt deliberately does not persist or display Hermes's freeform body-capture reason, preventing accidental evidence or secret URLs from appearing in cards or audit records. A failed five-second helper lock attempt returns only the fixed JSON `internal_error` result.

### Body-only exclusions

Install [the sample exclusion file](examples/body-capture-exclusions.conf) as `/etc/hermes-inspection-proxy/body-capture-exclusions.conf`, owned by `root:tlsproxy` with mode `0640`. The file starts empty. Each non-comment line is one normalized **exact** DNS hostname. The root-owned `[body_capture_exclusions] allowed_hosts` policy also starts empty. An administrator must first review and add an exact hostname to that policy; the configured operator can then request `/deadbolt exclusion_add <hostname>` or `/deadbolt exclusion_remove <hostname>`. Each command creates a separate Discord approval card showing the specific change and complete resulting list. The root executor binds that list and the prior file digest to the approval hash, then atomically replaces the fixed file only if its prior contents still match. Hermes ingress cannot request either edit.

The external proxy must use TLS SNI when present. If SNI is present but does not exactly match a listed hostname, it must **not** fall back to HTTP Host; normal body capture continues. It may use Host only when SNI is absent. Exact matching never includes subdomains implicitly. Exclusions suppress **only request and response body evidence**; the proxy must still route the traffic and retain DNS, connection metadata, firewall decisions, and audit records. [The reference matcher](src/deadbolt/exclusion_match.py) and its tests define this contract, but this repository does not contain the deployed proxy implementation. Verify the proxy behavior before using an approved exclusion. The proxy rereads the file, so Deadbolt runs no reload command.

No LLM provider is preapproved. Add external providers only after reviewing their current exact hostnames and updating root-owned policy. For a local LLM, establish a stable internal FQDN such as `llm.home.arpa` before adding it. Migrating a v0.5 suffix file requires a deliberate root-owned file and proxy update; do not reinterpret old suffix entries as exact-host approvals.

### Emergency stop and recovery

Only the configured Discord operator may run `/deadbolt emergency_stop` and `/deadbolt emergency_status`. Stop is idempotent: the root executor installs a dedicated `inet deadbolt_killswitch` nftables output rule dropping traffic whose socket UID is `hermes`, then stops `hermes-tls-proxy.service` and only optional units named in root-owned `[emergency_stop] workload_units` (empty by default). It records which units were active before stopping them. It does not stop `deadbolt-*` or `alloy.service`; their separate UIDs can continue delivering evidence. Hermes cannot reach these operations through its ingress socket.

Connectivity returns only after `/deadbolt emergency_recover` creates a **separate approval card** and the operator approves it. Recovery starts only the recorded previously active proxy and optional units, then removes the owned nftables table. A failed recovery reasserts the stop and remains audited. The root-owned state survives executor restart and reboot; `deadbolt-emergency-restore` reapplies the block in `ExecStartPre`. Install the shipped proxy dependency drop-in so the proxy cannot start if restoration fails. The local `/var/log/deadbolt/audit.jsonl` stream records requests, approvals, stop/recovery transitions, and failures; the existing root-owned `deadbolt-audit-relay.service` copies it to `/var/lib/alloy/deadbolt-audit/audit.jsonl`, which Alloy ships to Argus Loki with `source="deadbolt-audit"`. This release does not modify Alloy or Argus configuration.

The independent last-resort kill switch is **hypervisor power-off**. Deadbolt's software stop assumes the host kernel, root-owned state, nftables, and systemd remain trustworthy.

Pending approval expires after 10 minutes. UFW active TTL starts after successful application, defaults to 30 minutes, and is capped at 60 minutes and by the chosen profile. Expired UFW grants are swept every five seconds; startup reconciliation runs before the executor accepts requests. If rollback fails, the record stays recoverable and the executor retries. Body-capture expiry is enforced by the external helper and timer, not by the Deadbolt sweep.

## Deployment templates

Sanitized configuration lives in `examples/`; systemd templates live in `systemd/`; the capture helper lives in `scripts/`; log rotation templates live in `logrotate/`. Production configuration belongs only in `/etc/deadbolt/`, with root-owned policy, state, and audit paths. The `deadbolt` account must be a dedicated non-login user with no sudo or privileged supplementary groups. `zeus` remains the human/operator account and is not used by the bot. The root executor is the only privileged Deadbolt process. The ingress directory is `deadbolt:hermes` mode `0750`; its socket is mode `0666` *inside that private directory* and still checks the peer UID. The root socket is `root:deadbolt` mode `0660` under a root-owned runtime directory.

Install and run the tmpfiles definition before starting the units. It creates the private ingress directory and the UFW and iptables lock files needed by the executor's `ProtectSystem=strict` sandbox. Install `nftables` before starting the executor. Place `systemd/hermes-tls-proxy-deadbolt.conf` at `/etc/systemd/system/hermes-tls-proxy.service.d/deadbolt.conf` and reload systemd before testing reboot recovery. When testing body capture, ensure `/etc/hermes-inspection-proxy` exists. The executor unit permits atomic writes there for the fixed helper and approved exclusion file; the path is optional on UFW-only hosts.

### Versioned capture host files

The repository includes the helper and the currently used expiry and rotation templates. On a controlled host, compare these files to the installed versions and install them as root:

```sh
install -o root -g root -m 0750 scripts/hermes-body-capture /usr/local/sbin/hermes-body-capture
install -o root -g root -m 0644 systemd/hermes-body-capture-expiry.service /etc/systemd/system/
install -o root -g root -m 0644 systemd/hermes-body-capture-expiry.timer /etc/systemd/system/
install -o root -g root -m 0644 logrotate/hermes-proxy-evidence /etc/logrotate.d/
install -o root -g root -m 0644 logrotate/hermes-proxy /etc/logrotate.d/
systemctl daemon-reload
systemctl enable --now hermes-body-capture-expiry.timer
/usr/local/sbin/hermes-body-capture --json status
```

The helper writes `/etc/hermes-inspection-proxy/evidence.env` by atomic replacement and maintains a root-owned lock file in the same directory, then restarts the existing `hermes-tls-proxy.service`. The proxy must already consume `HERMES_CAPTURE_BODIES`, `HERMES_BODY_CAPTURE_MAX_BYTES`, and `HERMES_BODY_CAPTURE_EXPIRES_AT` from that file. The timer invokes `expire-if-due` every minute, even when Deadbolt is stopped, and starts again after reboot. Check `systemctl list-timers hermes-body-capture-expiry.timer` and the helper's JSON status before enabling the Deadbolt profile. Both rotation templates use `copytruncate` so a running proxy keeps writing to the same log file after rotation. The evidence template requests hourly rotation with 24 archives; configure the host's logrotate scheduler to invoke it hourly. `copytruncate` has a brief copy/truncate window in which log lines can be lost. The Argus Loki retention policy and the proxy service itself are not included here.

Deployment source should be a pinned release under `/opt/deadbolt`, owned by root and not writable by `hermes` or `deadbolt`. Review concrete root-owned UFW profiles, Discord IDs, and service permissions before rollout.

Teleport identity issuance, renewal, and revocation remain disabled. Generic service actions have no permitted profiles. Existing Teleport session recording and Argus telemetry are external to Deadbolt; this project does not change them.

## License

Apache-2.0. See [LICENSE](LICENSE).
