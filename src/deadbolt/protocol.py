"""Bounded, strict newline-delimited JSON over local Unix sockets."""

from __future__ import annotations

import asyncio
import json
import socket
import struct
from typing import Any

VERSION = 1
MAX_MESSAGE_BYTES = 16_384


class ProtocolError(ValueError):
    pass


def decode_message(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_MESSAGE_BYTES or not raw.endswith(b"\n"):
        raise ProtocolError("invalid message length or framing")
    try:
        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ProtocolError("duplicate JSON field")
                value[key] = item
            return value

        value = json.loads(raw[:-1].decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(value, dict) or value.get("version") != VERSION or type(value.get("version")) is not int:
        raise ProtocolError("unsupported protocol version")
    return value


def require_fields(message: dict[str, Any], required: set[str], optional: set[str] = frozenset()) -> None:
    if set(message) - {"version"} - required - optional or required - set(message):
        raise ProtocolError("unexpected or missing fields")


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5)
    except (asyncio.TimeoutError, asyncio.LimitOverrunError, asyncio.IncompleteReadError) as exc:
        raise ProtocolError("message read failed") from exc
    return decode_message(raw)


async def write_message(writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
    raw = (json.dumps({"version": VERSION, **payload}, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("response too large")
    writer.write(raw)
    await writer.drain()


def peer_uid(sock: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ProtocolError("Linux SO_PEERCRED is required")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


async def rpc(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(path, limit=MAX_MESSAGE_BYTES + 1)
    try:
        await write_message(writer, payload)
        return await read_message(reader)
    finally:
        writer.close()
        await writer.wait_closed()
