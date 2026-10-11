# Managed SSH broker (proposed deployment)

This feature is disabled in the example policy and this PR does not change a live
firewall or key. Enable it only after an operator completes the migration below
on a controlled host. It supports **noninteractive commands on enrolled targets**.
Targets without the fixed receiver may have another connectivity policy, but
Hermes cannot execute commands on them through this broker.

## Boundary

```text
Hermes -- structured JSON --> deadbolt bot -- approved session --> root executor
                                                               | exact nft guard
                                                               | exact UID UFW accept
                                                               v
                                           deadbolt-ssh transient systemd unit
                                                               | pinned IP:22, broker key
                                                               v
                                  target forced-command deadbolt-remote-exec
```

The bot still runs as `deadbolt` without sudo. The broker is a separate
non-login `deadbolt-ssh` account. Hermes must not read its key, access an
agent socket, change its policy, or hold a direct SSH exception. The root
executor creates the session, persists the exact IP and expiry, and launches
each SSH command in a hardened per-request unit as `deadbolt-ssh`. The unit
denies all network addresses except the approved IP. OpenSSH has PTY and
forwarding disabled and uses a pinned, root-owned known-hosts file.

The early `inet deadbolt_ssh` output hook is an additional broker-wide deny:
TCP/22 from `deadbolt-ssh` to any address outside the timed exact-IP set drops.
An early nftables accept does **not** bypass UFW. Deadbolt also inserts an
exact destination, TCP/22, `deadbolt-ssh` UID accept at the top of
`ufw-user-output`. That accept has its own UTC expiry match, so it stops
matching even if nftables is reset before Deadbolt reconciles. Ordinary
host-wide `ufw allow out` is never used for
session grants. The executor checks the guard and reinstalls missing exact
UFW accepts on startup and every reconciliation pass (currently five seconds),
including after UFW reload. Nftables set timeouts independently end access if
Deadbolt stops. Failure to restore the guard prevents executor startup.

## Root-owned profile

`[access_profiles.ssh-session]` in `/etc/deadbolt/profiles.toml` must define
`direction="out"`, `protocol="tcp"`, `ports=[22]`, a maximum TTL no greater
than 3600 seconds, `target_types` (`ip` and/or `dns`), canonical
`allowed_cidrs` and/or `allow_public`, `operator_approval=true`, and
`audited_execution=true`. It must also define a fixed SSH user, a key under
`/etc/deadbolt/keys/`, a known-hosts file under
`/etc/deadbolt/known-hosts/`, a list of 1–16 receiver command names, and a
`max_commands` limit from 1 to 100. `audit_output` is `metadata` by default;
`full` requires the restricted sink below.
The example is commented out. HTTP/HTTPS are durable baseline connectivity,
so `https-web` and `https-api` are intentionally unavailable as temporary
profiles.

The profile allows the named family and target boundary; it does not authorize
a CIDR-sized grant. Every active grant pins one exact IPv4 or IPv6 address.
DNS is resolved by root at request time, approval time, and before each
command. Empty, mixed allowed/disallowed, multi-address SSH, and changed
answers fail closed. The pinned IP is used for SSH and firewall rules; no
hostname-based firewall rule is created.

## Hermes request contract

Each message is one versioned, newline-terminated JSON object (16 KiB max) to
`/run/deadbolt/ingress/hermes.sock`. Unknown fields and malformed types fail.

```json
{"version":1,"op":"submit","action":"access_grant","profile":"ssh-session","destination":"managed.example","purpose":"Build SysReptor","ttl_seconds":900,"command":["uptime"]}
```

The operator card shows the normalized host, pinned IP, TCP/22, fixed SSH
user, purpose, TTL, command limit, and the first command name, argument count,
and SHA-256 of its exact argv. Argument values stay out of Discord. The approval is
bound to the canonical hash, request ID, and one-time nonce. Approval creates
one bounded session; it does not execute the first command automatically.

After approval, Hermes sends separate session-bound commands:

```json
{"version":1,"op":"ssh_execute","request_id":"APPROVED_UUID","destination":"managed.example","argv":["uptime"]}
```

The first execution must match the approved argv exactly. Later argv may use
only profile-listed command names. Each request is bounded (16 arguments,
256 bytes per argument, 2048 bytes total), validated against the target
receiver's root-owned command map, counted against the session limit, and
audited individually. There is no shell string, interactive PTY, port
forwarding, or direct Hermes SSH path. A command outside the list, a changed
target, expired session, or exhausted count needs a **new** approval.
The response contains only request ID, command index, exit code, and finish
time; stdout/stderr never go to Hermes or Discord.

The configured Discord user in the configured guild/channel can use
`/deadbolt status <request-id>` to inspect state and
`/deadbolt access_revoke <request-id>` to revoke immediately. Hermes ingress
cannot revoke or query privileged status. Denial, expiry, command failures,
reconciliation, and revoke appear in the existing root-owned JSONL audit
stream, relayed to Argus as before. The ordinary stream records timestamps,
approval ID, request ID, index, target/IP, user, an argv hash and count,
exit code, termination state, and explicit truncation flags. It contains no
full-mode argument values or command output. Purpose remains short and
secret-free.

Set `audit_output="full"` only in a root-owned profile and configure
`restricted_ssh_audit_path="/var/log/deadbolt/ssh-evidence.jsonl"` in the
root-owned executor config. This exact Hermes source path is the required
input to a **separate restricted Argus collection pipeline**; the proposed
restricted destination is `/var/lib/argus/deadbolt-ssh/evidence.jsonl` on
Argus. Neither path is collected by the ordinary Deadbolt audit relay or
ordinary Loki/Grafana stream. The local source is root-owned mode 0600.
Provision the restricted collector and access controls separately before
enabling a full profile. This PR does not deploy or configure Argus.

For full mode, the restricted JSONL file contains one `ssh_execution_started`
event, durably appended before the SSH child starts, and one
`ssh_execution_completed` event per command. Both include the exact structured
`argv`, request ID, approval ID, execution ID, command index, destination,
pinned IP, SSH user, and timestamp. Completion adds start/finish times, exit
code, `termination` (`exit`, `signal`, or `timeout`), `timed_out`, and separate
`stdout_b64` and `stderr_b64` fields. Base64 preserves arbitrary bytes without
redaction. Each decoded stream is capped at **65,536 bytes**; a corresponding
`stdout_truncated` or `stderr_truncated` boolean is true if more bytes were
produced. Excess bytes are drained and discarded. Truncation is never silent.
The restricted SQLite outbox also contains these records until delivery.
If emergency stop cancels a running command, the restricted stream instead
receives `ssh_execution_interrupted` with the exact argv, request/approval/
execution IDs, command index, target, timestamps, `reason="emergency_stop"`,
and `output_incomplete=true`. The broker child streams bounded progress to the
root executor while it runs. The interruption record includes any stdout and
stderr bytes received before cancellation as separate base64 fields, with
explicit truncation flags. Bytes still buffered in the remote process or
transport at termination may be unavailable; `output_incomplete` makes that
limit explicit. The ordinary audit stream receives only interruption metadata.
The root-owned state database also holds the initial canonical argv for
approval binding. Treat the database, outbox, and restricted file as sensitive
evidence; none is an input to the ordinary Argus relay.

Before granting full mode, Deadbolt checks that the restricted file is private
and writable. A restricted start-record flush failure prevents execution and
revokes the grant. A completion-record flush failure marks the execution
failed for inspection and revokes the grant. A completed SSH result is returned
only after the completion evidence is durably queued and flushed. On restart,
incomplete evidence delivery closes the session. Metadata mode retains its
prior output-discarding behavior and needs no restricted sink.

Deployment verification: configure the restricted Argus collector for the
Hermes source path above with access limited to authorized reviewers, verify
its destination is the restricted Argus path, and confirm neither the ordinary
`/var/log/deadbolt/audit.jsonl` relay nor Loki/Grafana ingests this file. Then
enable a test full profile, run one harmless command, confirm start and
completion records on the restricted destination with matching event IDs,
and verify no argv values or output appear in Discord or the ordinary audit
stream. Keep the full profile disabled if any check fails.

## Target receiver

Bootstrap each managed target from its VM console. Install
`scripts/deadbolt-remote-exec` as root-owned mode 0755 at
`/usr/local/libexec/deadbolt-remote-exec`, with the Deadbolt Python package
available to the target Python interpreter. Create a root-owned mode 0644 or
stricter `/etc/deadbolt/remote-commands.json` that maps command names to
fixed root-owned executable wrappers. Keep those wrappers under
`/usr/local/libexec/deadbolt-commands/`; they should implement exact allowed
operations and validate their own arguments. The receiver accepts one JSON
`{"version":1,"argv":[...]}` frame on stdin and uses `execve` with no shell.

Authorize only the dedicated broker public key on the target. Set its
`authorized_keys` entry to force
`command="/usr/local/libexec/deadbolt-remote-exec"`, with
`restrict,no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`.
Pin the target host key in the broker's known-hosts file. On the Hermes VM,
store the private key as root:`deadbolt-ssh` mode 0640 in
`/etc/deadbolt/keys/`; the parent directories must be root-owned and
nonwritable by Hermes. Do not use or reuse Hermes's current key.

## Migration and rollback

1. Install `systemd/deadbolt-ssh.sysusers.conf` as
   `/etc/sysusers.d/deadbolt-ssh.conf` and run `systemd-sysusers`.
   Confirm the account has no login, sudo, or privileged supplementary
   groups. Stage its key, known-hosts file, and target receiver.
2. Review the live UFW/nftables order. Remove **both** the Hermes UID
   SysReptor TCP/22 exception in `ufw-before-output` and the host-wide
   SysReptor TCP/22 accept in `ufw-user-output`. Remove the Hermes-owned
   SysReptor key authorization on the target. Verify direct Hermes TCP/22 is
   denied and no host-wide SSH exception remains.
3. Enable a narrow root-owned `ssh-session` profile, start the executor, and
   verify its early nft guard. Check the broker with one short approved
   session in a controlled environment. Inspect exact nft and UFW entries,
   command audit events, revoke, expiry, UFW reload, executor restart, and
   reboot recovery before production use.
4. For rollback, disable the profile and revoke/expire active sessions first.
   Keep the broker-wide deny guard until all broker credentials and grants are
   removed. Restore any baseline access only through a separate, reviewed
   change; do not reinstate the prior host-wide SSH exception.

The separate `deadbolt-baseline verify` / `apply` command manages durable
non-approval UFW rules from root-owned
`/etc/deadbolt/baseline-egress.toml`: DNS TCP/UDP53 only to the configured
Pi-hole, outbound TCP80/443, Wazuh TCP1514/1515 and Loki TCP3100 only to
configured Argus. This PR ships a sample with the current lab IPs but does
not run `apply`; it does not alter emergency-stop behavior or Argus config.
