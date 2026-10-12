# Approved recorded outbound SSH and raw access

This feature is **disabled** in the example policy. The PR supplies code and
isolated tests; it does not deploy an SSH proxy, modify Hermes or Argus, move a
key, or change live UFW rules. The on-host acceptance test remains required.

## Request and approval contract

Hermes sends one versioned JSON object per Unix-socket exchange to
`/run/deadbolt/ingress/hermes.sock` (16 KiB maximum). Unknown fields fail.
The destination is a canonical **literal IPv4 or IPv6 address**. DNS names,
URLs, CIDRs, special-use addresses, and whitespace are rejected. Root checks
the IP against its configured CIDR/public boundary. A single approval binds
the exact IP, port, transport, purpose, requested duration, request ID, nonce,
and canonical action hash. The operator sees these values on the Discord card.

```json
{"version":1,"op":"submit","action":"outbound_access","kind":"ssh","destination":"192.168.1.205","port":22,"purpose":"SysReptor build","ttl_seconds":3600}
```

```json
{"version":1,"op":"submit","action":"outbound_access","kind":"raw","destination":"192.168.1.205","port":22,"transport":"tcp","purpose":"Uninspected break glass","ttl_seconds":3600}
```

`kind` is mandatory: omission never means raw. Raw requires exactly one of
`tcp` or `udp`. The card warns that raw contents may be invisible. Raw TCP/22
requires the separate **Approve uninspected SSH** button and an explicit root
confirmation flag. It deliberately bypasses recording. Raw TCP/80 and TCP/443
are rejected because those transports are already baseline-open and an exact
temporary grant would be misleading. The root-configurable maximum is at most
24 hours; one hour is a client suggestion, not a hard limit. The example
policy permits nothing until configured.

On approval of `ssh`, the result contains `proxy_host="127.0.0.1"` and the
root-configured `proxy_port`. Hermes authenticates to that loopback listener
with its dedicated proxy client key. It must pin the proxy host key in a
root-controlled known-hosts entry and enable strict host-key checking. The
proxy accepts only that client public key and verifies the grant's exact
destination and deadline; a client-supplied target cannot override the grant.
One approval permits multiple concurrent SSH sessions, each with a different
evidence session ID. There is no per-command approval or command-count limit
for the intercepted SSH mode. The legacy target-receiver broker described in
`ssh-broker.md` remains a separate, optional mode.

Hermes can query its own request with:

```json
{"version":1,"op":"outbound_status","request_id":"APPROVED_UUID"}
```

The configured Discord operator can use `/deadbolt status` and
`/deadbolt outbound_revoke`. Hermes cannot revoke or approve. Expiry,
revoke, emergency stop, and proxy failure end the grant and sessions; status
instructs Hermes to request a new approval. There is no renewal.

## Enforcement

`deadbolt-ssh-proxy` is a dedicated non-login Unix service account. The proxy
unit listens only on `127.0.0.1`. Its fixed upstream target user, private key,
and SHA-256 host-key pin come from root-owned `[outbound_access.ssh_targets]`.
The target needs no receiver or software change. The target key must move from
Hermes-readable storage into `/etc/deadbolt-ssh-proxy/keys/`. Keep every
parent directory root-owned and free of group/other write permissions; give
the proxy group traversal (for example root:deadbolt-ssh-proxy mode `0750`)
and make private keys root:deadbolt-ssh-proxy mode `0640`. Keep the client
public-key pin root-owned and non-writable by other accounts. Remove Hermes's
old key copy and authorization path after a
successful cutover. This key is **not** the legacy forced-command broker key.
The dedicated Hermes-to-proxy client key is separate. SSH-MITM 6.0.0 terminates
both SSH legs; Deadbolt supplies strict authentication and evidence hooks.

Before the proxy starts, root installs an early `inet deadbolt_ssh_proxy`
output guard. It drops all direct `hermes` TCP/22 and all non-loopback proxy
account egress except an active timed exact-IP:port set entry. An exact
UID/destination/port UFW accept is inserted **before** the matching LAN or
SSH deny, with its own UTC deadline. An nft accept alone cannot override a
later UFW deny. Raw TCP/UDP grants other than TCP/22 also use an early timed
nft allow followed by a persistent Deadbolt-owned exact-endpoint drop. When
the timed element expires or is revoked, that drop precedes UFW's
`ESTABLISHED` accept, so an open raw connection cannot keep sending. The
owned drop entry remains until the nft table is deliberately recreated or
the host reboots; a fresh approved grant to the same endpoint can activate
it again. The executor checks both layers on approval and every
reconciliation pass, including after UFW reload. The independent nft timeout
and UFW time match stop permitting a packet after expiry even if Deadbolt is
down; the executor removes owned rules on restart. Raw TCP/22 is a separate
exact Hermes-UID rule and never created by an `ssh` approval.

At migration, remove the old Hermes UID and host-wide static SysReptor
TCP/22 accepts from the controlled UFW chains. Do this as an explicit host
change after reviewing the current rules; the PR does not remove them live.
Verify that direct Hermes-to-target **TCP/22** fails before, during, and after a
proxied grant. This is not an all-port SSH block: a target listening on
baseline-open public TCP/443 may still be reachable outside the recording
proxy. Preserve the durable DNS, HTTP/HTTPS, Wazuh, and Loki baseline
rules. Emergency stop blocks Hermes and all proxy-account outbound traffic,
revokes grants, and stops the proxy service while Deadbolt and Alloy continue.

## Evidence path

SSH-MITM calls the Deadbolt hooks before forwarding each input/output chunk.
The proxy writes per-session JSONL frames containing byte-exact base64 data
and fsyncs each frame first. Frames include `session_started`, `exec_request`,
`stdin`, `stdout`, `stderr`, and a completion/failure marker. A final manifest
has the SHA-256 of all frames, frame count, request/session IDs, finish time,
and reason. The independently running exporter checks for unlocked orphan
sessions on every pass, without requiring another grant or proxy startup.
It marks them `proxy_crash` with `output_incomplete=true` and delivers their
manifest to Argus. A partially written final frame stays byte-exact in the
restricted Argus file and appears as a `recovery_tail` event in restricted
Loki; the manifest marks `partial_frame=true`. This is restricted evidence; it may
contain credentials. The ordinary Deadbolt audit, Discord, and Hermes status
contain metadata only.

The explicit maximum transcript is **32 MiB per session**. If a chunk would
exceed it, or local free space drops below **64 MiB**, forwarding stops and
the session fails; bytes are never silently truncated. The spool is private
to `deadbolt-ssh-proxy` under `/var/lib/deadbolt-ssh-proxy/ssh-spool`. The root-owned
exporter retries complete manifests over mutually authenticated TLS. An Argus
receiver writes root-only per-session files under
`/srv/argus/deadbolt/ssh-transcripts` and sends searchable frame text and
metadata to a **separate restricted Loki endpoint and tenant**. It
acknowledges a manifest/checksum only after the complete transcript is stored
and the restricted Loki ingestion acknowledges every batch. Hermes marks a
session delivered only after that matching Argus ACK. A local Argus outage can
create a backlog; the exporter logs a backlog alert and retries. Configure
both retention and access control on Argus before enabling this feature.

The Argus receiver and restricted Loki destination are **not currently
deployed**. The receiver service requires a root-only
`/etc/deadbolt-transcripts/receiver.env` with
`DEADBOLT_RESTRICTED_LOKI_URL` and
`DEADBOLT_RESTRICTED_LOKI_TENANT`; it refuses the ordinary default local Loki
endpoint. The Hermes exporter requires a root-only
`/etc/deadbolt/ssh-exporter.env` with `DEADBOLT_ARGUS_HOST` and
`DEADBOLT_ARGUS_PORT`, plus a pinned CA and mTLS client certificate/key.
Provision the Argus 700 GB disk directory root-only and verify its restricted
Loki tenant cannot be read through ordinary Grafana or Loki credentials.
Do not enable SSH policy until this pipeline is configured and tested.

## Controlled deployment and acceptance

1. Install a pinned `ssh-mitm==6.0.0` package in the root-owned Deadbolt
   environment and the shipped proxy/exporter/expiry units. Create the
   `deadbolt-ssh-proxy` non-login account and private tmpfiles directories.
   Compare the vendor binary/source hash and review the installed dependency.
2. Create fixed host and client key pins. Verify the target fingerprint from
   a trusted console. Move the target authentication key into proxy-only
   storage and remove Hermes read access. Configure the exact root-owned
   target entry and an allowed destination CIDR. Leave other targets absent.
3. Configure the Argus mTLS receiver and restricted Loki endpoint, start the
   exporter, and prove a manifest is ACKed only after the complete restricted
   transcript and searchable text arrive. Simulate Argus downtime and a full
   local spool; prove backlog/retry or refusal without dropped bytes.
4. Remove the two static SysReptor SSH exceptions. Confirm direct Hermes
   TCP/22 fails. Approve a one-hour `ssh` grant and hold a live proxied
   Hermes-to-SysReptor session for **five minutes**. Run `id` and read
   `/etc/os-release` interactively. Find the actual input and output on Argus
   by session ID, then confirm direct Hermes TCP/22 still fails during and
   after the grant.
5. Repeat with expiry, operator revoke, emergency stop, proxy failure,
   evidence-sink failure, UFW reload, and reboot. Verify no direct rule is
   added for `ssh`, that active sessions close, and that recovery requires a
   new approval. Separately check a deliberately approved raw TCP/22 grant
   warns about bypassing inspection.

The isolated CI suite uses a mock target and a network-disabled firewall
container. It does **not** prove the Hermes-to-SysReptor-to-Argus deployment
works. Record the host acceptance results before calling this operational.
