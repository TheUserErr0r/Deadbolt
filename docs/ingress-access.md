# Temporary inbound listener grants

This opt-in feature grants **new target-initiated connections** to a Hermes
listener. `deadbolt-access request raw` remains outbound only. An established
response to a Hermes-initiated flow is different from a new callback.
Deadbolt changes only the inbound firewall scope; it does not start a listener
or change outbound access.

## Root-owned policy

The example policy leaves ingress disabled. A reviewed administrator may add
this stanza to the private `/etc/deadbolt/profiles.toml`:

```toml
[ingress_access]
enabled = true
max_ttl_seconds = 3600
max_port_width = 5
allowed_source_cidrs = ["192.168.1.0/24"]
```

The defaults are 60 minutes and five consecutive ports. Root policy can set
lower or higher limits up to hard ceilings of 24 hours and 16 ports. A source
must be a canonical literal IPv4/IPv6 address or canonical CIDR of no more
than 256 addresses, wholly inside a reviewed policy CIDR. The destination
must be a canonical private LAN IP currently assigned to a non-loopback
Hermes interface. Root rejects loopback, public destinations, ports below
1024, mixed address families, and broad or ambiguous sources. Partially
overlapping active grants are rejected. A newly approved request for the
same exact source, local IP, protocol, and port range replaces the old grant:
Deadbolt revokes the old rule before installing and verifying the new one.
The new TTL starts from this approval, not from the old expiry. A pending or
denied request never changes the active grant; if old-rule revocation fails,
the new request fails closed and reconciliation retries the old rollback.
Both request IDs and the replacement are audited. Policy changes invalidate
pending approvals; removing a source boundary revokes active grants on
reconciliation. Restart the executor after
enabling ingress so it initializes the firewall adapter.

## Request and approval

```sh
deadbolt-access request ingress \
  --protocol tcp \
  --source-ip 192.168.1.205 \
  --local-ip 192.168.1.102 \
  --port 6969-6973 \
  --ttl 30m \
  --reason 'CTF callback window'
```

This CTF example is a request, not an active grant. The CLI sends strict
protocol v1 JSON to `/run/deadbolt/ingress/hermes.sock`:

```json
{"version":1,"op":"submit","action":"ingress_access","protocol":"tcp","source_ip":"192.168.1.205","local_ip":"192.168.1.102","port_start":6969,"port_end":6973,"ttl_seconds":1800,"reason":"CTF callback window"}
```

The bot checks the Hermes peer UID. Root validates the policy and local IP,
constructs a canonical hash, and shows the exact source, destination,
protocol, ports, TTL and reason on the Discord card. Only the configured
operator in the configured guild/channel may approve. Denial and ten-minute
pending expiry cause no firewall change. Hermes cannot submit rule syntax.

## Status, revoke, and expiry

```sh
deadbolt-access status
deadbolt-access revoke <grant-id>
```

Hermes may inspect and idempotently revoke its own active ingress grants.
Status includes ID, source, destination, protocol, ports and expiry. Root
stores rollback intent and emits request, decision, application, revoke,
expiry and failure events through the existing SQLite audit outbox into
`/var/log/deadbolt/audit.jsonl`. The existing audit relay can ship these to
Argus without a new Argus configuration.

The exact UFW accept is inserted before UFW's established-traffic accept.
An earlier nftables input guard uses a timed set to allow the approved tuple
and drop it after expiry, including already-established traffic. The UFW
accept has an independent wall-clock stop date. The executor removes its own
accept on revoke or expiry and reconciles active grants after restart, reboot
or UFW reload. Failed verification does not mark a request active; rollback
intent remains for retry or inspection. Unrelated rules and outbound policy
are untouched.

## Verification before use

Repository tests exercise exact source/port matching, held TCP connections
across revoke and expiry, and repeated apply/remove in a network-disabled
container. On a controlled host, verify UFW is active with default incoming
deny, the local IP is assigned, out-of-scope source/port traffic is blocked,
the active flow stops at expiry, and audit events arrive as expected. This PR
does not deploy policy or run a live Hermes callback.
