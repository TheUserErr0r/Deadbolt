"""Unprivileged structured request client for the Hermes-facing bot socket."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from pathlib import Path
import sys
import uuid

from deadbolt.protocol import INGRESS_RESPONSE_TIMEOUT_SECONDS, rpc


def _ttl(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]{0,5})([smh]?)", value)
    if match is None:
        raise argparse.ArgumentTypeError("TTL must be seconds or a positive value ending in s, m, or h")
    seconds = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]
    if seconds > 24 * 3600:
        raise argparse.ArgumentTypeError("TTL exceeds the hard 24-hour limit")
    return seconds


def _ports(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?", value)
    if match is None:
        raise argparse.ArgumentTypeError("port must be a single integer or explicit low-high range")
    lo, hi = int(match[1]), int(match[2] or match[1])
    if not 1024 <= lo <= hi <= 65535 or hi - lo >= 16:
        raise argparse.ArgumentTypeError("port must be unprivileged and range at most 16")
    return lo, hi


def _id(value: str) -> str:
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise argparse.ArgumentTypeError("grant ID must be a canonical UUID") from exc
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="deadbolt-access",
        description="Submit structured requests to the local Deadbolt approval bot")
    result.add_argument("--socket", type=Path,
                        default=Path("/run/deadbolt/ingress/hermes.sock"))
    commands = result.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request")
    kinds = request.add_subparsers(dest="kind", required=True)
    ingress = kinds.add_parser("ingress", help="request a temporary inbound listener")
    ingress.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    ingress.add_argument("--source-ip", required=True)
    ingress.add_argument("--local-ip", required=True)
    ingress.add_argument("--port", type=_ports, required=True)
    ingress.add_argument("--ttl", type=_ttl, required=True)
    ingress.add_argument("--reason", required=True)
    for kind in ("ssh", "raw"):
        outgoing = kinds.add_parser(kind, help="request existing outbound access")
        outgoing.add_argument("--ip", required=True)
        outgoing.add_argument("--port", type=int, required=True)
        outgoing.add_argument("--ttl", type=_ttl, required=True)
        outgoing.add_argument("--reason", required=True)
        if kind == "raw":
            outgoing.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    commands.add_parser("status", help="list active inbound grants")
    revoke = commands.add_parser("revoke", help="revoke an owned inbound grant")
    revoke.add_argument("grant_id", type=_id)
    return result


def payload(args: argparse.Namespace) -> dict[str, object]:
    if args.command == "status":
        return {"op": "ingress_status"}
    if args.command == "revoke":
        return {"op": "ingress_revoke", "request_id": args.grant_id}
    if args.kind == "ingress":
        lo, hi = args.port
        return {"op": "submit", "action": "ingress_access", "protocol": args.protocol,
                "source_ip": args.source_ip, "local_ip": args.local_ip,
                "port_start": lo, "port_end": hi, "ttl_seconds": args.ttl,
                "reason": args.reason}
    request = {"op": "submit", "action": "outbound_access", "kind": args.kind,
               "destination": args.ip, "port": args.port, "ttl_seconds": args.ttl,
               "purpose": args.reason}
    if args.kind == "raw":
        request["transport"] = args.protocol
    return request


def main() -> None:
    args = parser().parse_args()
    request = payload(args)
    try:
        response = asyncio.run(rpc(str(args.socket), request,
            response_timeout_seconds=(INGRESS_RESPONSE_TIMEOUT_SECONDS
                                      if args.command in ("request", "revoke") else 5)))
    except (OSError, ValueError) as exc:
        print(f"Deadbolt request failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    if not response.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
