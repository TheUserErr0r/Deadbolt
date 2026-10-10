# Architecture and protocol

Deadbolt has three Unix privilege domains: `hermes` submits, `deadbolt` relays Discord decisions, and `root` owns policy and applies UFW or fixed body-capture operations. `zeus` is an interactive operator account outside the runtime path. No inbound HTTP service or public webhook is used. Discord uses its outbound Gateway and REST connections.

The `deadbolt` process binds `/run/deadbolt/ingress/hermes.sock` in a private directory. It accepts only `submit` from the `hermes` UID. The executor binds `/run/deadbolt/bot.sock` and accepts only the `deadbolt` UID. Both listeners check `SO_PEERCRED` before trusting a message. Each connection carries one versioned JSON line, limited to 16 KiB; unknown fields and protocol versions are rejected.

Root resolves a request from its own policy, builds a human-readable description, serializes the canonical action with sorted JSON keys, and hashes it with SHA-256. It stores the hash, request ID, nonce, deadline, and full action in SQLite. The bot fetches pending records, posts the root description, then reports the Discord message ID. Decisions include request ID, nonce, hash, message ID, and Discord interaction metadata. Root compares the metadata to its configured IDs, validates the one-time nonce and posted state, recomputes the stored hash, and re-resolves the current policy before acting. The root trusts the bot's assertion about the Discord interaction; it cannot inspect Discord independently.

```text
pending -> posted -> approved -> executing -> active -> rolled_back
     |         |         |            |            |
     +-> expired         +-> failed   +-> failed   +-> retry rollback on error
               +-> denied / expired
```

Each transition writes an audit outbox event in the same SQLite transaction. The outbox is flushed to root-owned JSON Lines with `O_APPEND`, `O_NOFOLLOW`, and `fsync`. Delivery is at least once; event IDs permit deduplication. The bot never reads SQLite or audit files. `pending` and `posted` expire after ten minutes. The active TTL begins only after UFW reports a successful and verified add. Startup reconciliation handles `approved`, `executing`, and overdue `active` records before serving IPC. Failed rollback remains recoverable and is retried on the five-second sweep.

UFW profiles fix direction, protocol, source CIDR, destination CIDR, port or narrow range, optional interface, and TTL. Before mutation, the executor checks existing added rules; an identical unmanaged rule yields a recorded no-op grant. A new rule gets a unique `deadbolt:<grant-id>` comment. The executor persists the intended rule and tag before applying it. Rollback refuses ambiguous or altered rules and deletes only a verified matching tag. All calls use fixed argv vectors and `shell=False`. UFW's textual CLI and concurrent external changes remain documented limits.

Body-capture enable has its own `pending -> posted -> approved -> executing -> active` path. The canonical action contains fixed `enable`, integer hours from 1 to 24, and no user-supplied command. A separate fixed helper returns the authoritative expiry. Subsequent enables supersede prior Deadbolt records; the external helper replaces the expiry from the current time. The helper's systemd timer, not Deadbolt's sweep, disables capture at expiry. A restart after an interrupted helper call leaves an audited `failed` record and requires operator inspection of the authoritative helper status. Operator-only Discord `capture_status` and `capture_disable` bypass the approval queue but still require the configured user, guild, and channel IDs and are audited through a durable operator outbox.

Exclusion replacement is another approval-gated path: `pending -> posted -> approved -> executing -> completed`. Root resolves the exact sorted DNS suffix list against its allow-list, displays it, persists a before-file digest and the approved replacement, then atomically replaces the fixed `root:tlsproxy` mode `0640` file. On restart, it compares the file to the intended replacement and before digest. The proxy is expected to reread that file and suppress bodies for matching SNI or Host suffixes while preserving routing, metadata, and firewall checks. Deadbolt does not install the proxy or implement its matching behavior.

Teleport and service actions are disabled. A future Teleport baseline renewer, if built, is independent of Deadbolt. This release does not alter production VMs, Discord credentials, or Argus integrations.
