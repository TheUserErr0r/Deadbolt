# Security model and reporting

Please report suspected security issues privately to the repository owner. Do not include credentials, real host details, or production logs in a public issue.

## Trust boundaries

- `hermes` may only submit a structured request to the bot-owned ingress socket. It cannot call the root executor socket, approve requests, edit root-owned policy or state, or access the Discord token.
- `deadbolt` is a dedicated non-login service account with no sudo or privileged supplementary groups. Any process running as this UID can act as the approval relay; `SO_PEERCRED` proves the Unix UID, not the Python process. A compromise of this UID can forge Hermes-origin requests and relay decisions within the root executor's fixed allow-list. The executor intentionally trusts the relay's assertions about the Hermes caller and configured Discord human.
- `root` owns the executor, policy, state database, audit file, root socket, UFW execution, and rollback. Compromise of root defeats Deadbolt's boundary.
- Discord account or bot-token compromise can affect the approval flow. Root still enforces action, profile, TTL, state, nonce, and canonical hash, but cannot independently authenticate a Discord interaction.

Deadbolt v0.5 does not claim to protect a host after a full root compromise. Its specific goal is preventing the unprivileged Hermes agent from directly elevating through this workflow.

## Action limits and recovery

Only named root-owned UFW profiles can be applied. Hermes cannot supply firewall rule fields, arbitrary destinations, ports, commands, or service units. The Teleport and service action interfaces fail closed. UFW output is text rather than a transactional machine API; Deadbolt refuses ambiguous matching rules and records rollback failures for operator attention. An external administrator changing UFW concurrently can still create a narrow race around a CLI operation. Keep profile scopes narrow and review existing firewall rules before deployment.

Rollback intent is committed before applying a rule. On restart, the executor reconciles interrupted executions and overdue grants before opening its socket. Periodic sweeps retry failed rollbacks. If the executor remains stopped, an active UFW rule can outlive its intended expiry until the executor restarts; a persistent systemd timer is a future defense in depth. A rule that cannot be positively identified as Deadbolt-owned is never deleted automatically.

Expiry uses the host wall clock so it can survive restarts. A root-level clock change can alter expiry behavior; accurate host time is part of the trusted operating environment.

SQLite state transitions and their audit outbox events commit together. JSON Lines delivery is at least once; a crash between append and outbox acknowledgment can duplicate an event, so each record has an event ID. The JSON Lines file is **root-owned and append-only by service design, not immutable against root**. Root can alter or delete it. Ship copies to an independent collector for stronger evidence retention.

## Existing external controls

Deadbolt v0.5 does not modify Teleport, Argus, firewall defaults, or existing Hermes egress controls. Teleport Community Edition records sessions routed through its proxy, but does not provide session and identity locks for immediate revocation. A separate 60-minute identity and 30-minute root-owned renewal service has been proposed; it is **not deployed** and Deadbolt does not depend on it. A copied certificate remains usable until its own expiry. Default-deny egress and the direct SSH controls already exist outside Deadbolt. HTTPS tunneling over permitted TCP/443 is a future TLS-inspection concern outside this release.

## Suggested host monitoring after deployment

Watch `/opt/deadbolt`, `/etc/deadbolt/`, `/var/lib/deadbolt/`, `/var/log/deadbolt/`, `/run/deadbolt/`, `deadbolt-executor.service`, `deadbolt-bot.service`, and the systemd tmpfiles definition with auditd and Wazuh. Changes to policy, source, service definitions, socket permissions, and failed rollback events deserve particular attention. No production auditd, Wazuh, Loki, Grafana, Alloy, or Teleport configuration is changed by this repository.
