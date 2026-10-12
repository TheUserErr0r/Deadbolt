# Security model and reporting

Please report suspected security issues privately to the repository owner. Do not include credentials, real host details, or production logs in a public issue.

## Trust boundaries

- `hermes` may only submit a structured request to the bot-owned ingress socket. It cannot call the root executor socket, approve requests, edit root-owned policy or state, or access the Discord token.
- `deadbolt` is a dedicated non-login service account with no sudo or privileged supplementary groups. Any process running as this UID can act as the approval relay; `SO_PEERCRED` proves the Unix UID, not the Python process. A compromise of this UID can forge Hermes-origin requests and relay decisions within the root executor's fixed allow-list. The executor intentionally trusts the relay's assertions about the Hermes caller and configured Discord human.
- `root` owns the executor, policy, state database, audit file, root socket, UFW execution, and rollback. Compromise of root defeats Deadbolt's boundary.
- Discord account or bot-token compromise can affect the approval flow. Root still enforces action, profile, TTL, state, nonce, and canonical hash, but cannot independently authenticate a Discord interaction.

Deadbolt v0.6 does not claim to protect a host after a full root compromise. Its specific goal is preventing the unprivileged Hermes agent from directly elevating through this workflow.

## Action limits and recovery

The opt-in [recorded outbound SSH proxy](docs/recorded-outbound-ssh.md) is a
separate path from the legacy managed-command broker below. The dedicated
`deadbolt-ssh-proxy` account, not Hermes, owns the fixed upstream key and
target host-key pin. Direct Hermes TCP/22 is dropped by an early nft guard,
and the proxy account receives only a timed exact-IP:port nft entry plus an
ordered UID-scoped UFW allow. The proxy records every forwarded SSH channel
chunk to a private, fsynced local spool before forwarding. Spool exhaustion,
write failure, revoked grant, or expiry terminates the session. Argus needs a
separate root-only transcript receiver and restricted Loki tenant; ordinary
audit/Discord never receive transcript bytes. Raw access has no content
inspection. Raw TCP/22 can deliberately bypass SSH recording only after a
prominent card warning and explicit operator confirmation. These features
are disabled until a deliberate host migration removes existing static SSH
exceptions and proves the restricted evidence path. The isolated tests cannot
prove those live deployment properties.

Only named root-owned UFW profiles, specifically enabled body-capture actions, and configured managed SSH profiles can be applied. Hermes cannot supply raw firewall rule fields, ports, service units, or shell commands. In a managed SSH profile, Hermes supplies a bounded destination, purpose, TTL, and structured argv; root resolves and pins the IP, and the target receiver runs only root-configured command wrappers. The Teleport and service action interfaces fail closed. UFW output is text rather than a transactional machine API; Deadbolt refuses ambiguous matching rules and records rollback failures for operator attention. An external administrator changing UFW concurrently can still create a narrow race around a CLI operation. Keep profile scopes narrow and review existing firewall rules before deployment.

Managed SSH is disabled by default. When enabled, the dedicated `deadbolt-ssh` account owns the only broker key. Hermes must not read or reuse it. The broker has an early nftables TCP/22 deny for every destination except an active exact pinned IP, plus an exact UID-scoped UFW accept before the UFW deny. The existing Hermes UID and host-wide SysReptor SSH exceptions must be removed during migration. Do not restore host-wide SSH access after a broker failure. The target must force `deadbolt-remote-exec` for the broker key and deny PTY and forwarding. This is noninteractive command execution, not a recording bastion. A compromised target wrapper, root policy, or broker key can exceed the intended command scope; review and isolate those assets.

The ordinary Deadbolt audit stream contains SSH metadata and a command summary; it never contains full-mode argv or stdout/stderr. Metadata-only profiles discard command output as before. A root-configured `audit_output="full"` profile writes exact argv and byte-exact bounded stdout/stderr to a separate root-owned restricted evidence file and its durable SQLite outbox. That file can contain credentials and sensitive target data by design. It must be collected into a separate restricted Argus store, never the ordinary Loki/Grafana pipeline. The ordinary Argus relay remains metadata-only for SSH. See the [SSH broker runbook](docs/ssh-broker.md).

Body capture is disabled in the example policy. If enabled, an approved request may call only `/usr/local/sbin/hermes-body-capture --json enable HOURS` with an integer from 1 through 24. The versioned helper and its root-owned systemd timer are separate from the Deadbolt daemon and authoritative for expiry; Deadbolt does not clean up capture at the deadline. The helper serializes calls and treats an enabled state with an invalid expiry as due for disable. Each new enable requires a fresh approval and replaces the old expiry. The configured Discord operator can directly invoke fixed `status` and idempotent `disable` helper operations; Hermes cannot submit those operations. A process compromised as `deadbolt` can impersonate that operator to the root executor, as stated above. The executor validates and audits only fixed JSON result fields and discards raw helper output and stderr. Freeform Hermes reasons for capture and exclusion edits are never persisted or sent to Discord, limiting accidental body, URL, or secret exposure through this channel.

The exclusion file is a root-owned `root:tlsproxy` mode `0640` integration point. Its initial active list and root-owned allow-list are empty. Only the configured Discord operator can request an add/remove card; Hermes ingress cannot request edits. Root atomically replaces the fixed file after a separate approval and a prior-file hash check. It accepts only exact DNS hostnames already reviewed into root-owned policy. If TLS SNI is present, the external proxy must compare that hostname exactly and must not fall back to HTTP Host on a mismatch. Host is considered only when SNI is absent. The proxy must suppress only body evidence while retaining routing, DNS and connection metadata, firewall controls, and audit logs. Deadbolt cannot enforce the proxy's matching behavior from its policy file; verify the deployed proxy implementation before enabling exclusions. No regex, wildcard, arbitrary file, or bypass action is exposed. Existing v0.5 suffix entries need explicit migration.

The emergency stop is operator-only. Root owns a dedicated `inet deadbolt_killswitch` nftables table dropping locally generated traffic with the `hermes` socket UID and TCP/22 traffic with the `deadbolt-ssh` UID. It cancels in-flight broker units, revokes active SSH grants, then stops `hermes-tls-proxy.service` and optional root-configured workload units. It never stops `deadbolt-*` or `alloy.service`. The rule does not stop root-owned sockets, traffic from other UIDs, or already copied credentials on another host; these are limits of a UID-based host control. Stopping the proxy closes the proxied HTTPS route while Alloy can continue forwarding evidence under its own account. The state and prior active service set are persisted under root-owned Deadbolt state. Recovery has a fresh Discord approval and starts only previously active units; revoked SSH grants require a fresh approval. Reboot restoration runs before executor start, and the shipped proxy dependency drop-in makes proxy startup fail if restore fails. A broken host kernel, nftables service, root-owned state, or systemd can defeat this software control. **Hypervisor power-off remains the independent kill switch.**

The shipped proxy log rotation templates use `copytruncate` to keep a long-running proxy on the current log inode. Logrotate can lose lines written during its copy/truncate window; the templates do not guarantee gap-free local evidence. Argus-side retention remains separately managed.

Rollback intent is committed before applying a rule. On restart, the executor reconciles interrupted executions and overdue grants before opening its socket. Periodic sweeps retry failed rollbacks. If the executor remains stopped, an active UFW rule can outlive its intended expiry until the executor restarts; a persistent systemd timer is a future defense in depth. A rule that cannot be positively identified as Deadbolt-owned is never deleted automatically.

Expiry uses the host wall clock so it can survive restarts. A root-level clock change can alter expiry behavior; accurate host time is part of the trusted operating environment.

SQLite state transitions and their audit outbox events commit together. JSON Lines delivery is at least once; a crash between append and outbox acknowledgment can duplicate an event, so each record has an event ID. The JSON Lines file is **root-owned and append-only by service design, not immutable against root**. Root can alter or delete it. On Hermes, a root-owned `deadbolt-audit-relay.service` copies this stream to `/var/lib/alloy/deadbolt-audit/audit.jsonl`; Alloy ships it to Argus Loki as `source="deadbolt-audit"`. This release reuses that stream and does not change Alloy or Argus configuration.

## Existing external controls

Deadbolt v0.6 does not modify Teleport, Argus, firewall defaults, or the existing Hermes egress policy outside its dedicated emergency nftables table. Teleport Community Edition records sessions routed through its proxy, but does not provide session and identity locks for immediate revocation. A separate 60-minute identity and 30-minute root-owned renewal service has been proposed; it is **not deployed** and Deadbolt does not depend on it. A copied certificate remains usable until its own expiry. Default-deny egress and the direct SSH controls already exist outside Deadbolt. HTTPS tunneling over permitted TCP/443 remains outside this release when the emergency stop is inactive.

## Suggested host monitoring after deployment

Watch `/opt/deadbolt`, `/etc/deadbolt/`, `/var/lib/deadbolt/`, `/var/log/deadbolt/`, `/run/deadbolt/`, `deadbolt-executor.service`, `deadbolt-bot.service`, and the systemd tmpfiles definition with auditd and Wazuh. Changes to policy, source, service definitions, socket permissions, and failed rollback events deserve particular attention. No production auditd, Wazuh, Loki, Grafana, Alloy, or Teleport configuration is changed by this repository.
