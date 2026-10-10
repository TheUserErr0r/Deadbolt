"""Unprivileged Hermes ingress and Discord approval relay."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import pwd
import socket
import stat
import time
from typing import Any, Awaitable, Callable

from deadbolt.protocol import MAX_MESSAGE_BYTES, ProtocolError, peer_uid, read_message, require_fields, rpc, write_message

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class BotConfig:
    hermes_socket: Path
    executor_socket: Path
    hermes_user: str
    user_id: str
    guild_id: str
    channel_id: str
    token: str | None
    dry_run: bool

    @classmethod
    def environment(cls, dry_run: bool) -> BotConfig:
        token = os.environ.get("DEADBOLT_DISCORD_TOKEN")
        if not dry_run and (not token or token.startswith("REPLACE_")):
            raise ValueError("DEADBOLT_DISCORD_TOKEN is required outside dry-run mode")
        ids = [os.environ.get(name, "0") for name in
               ("DEADBOLT_USER_ID", "DEADBOLT_GUILD_ID", "DEADBOLT_CHANNEL_ID")]
        if any(not value.isdecimal() or (not dry_run and value == "0") for value in ids):
            raise ValueError("Discord IDs must be decimal strings")
        return cls(Path(os.environ.get("DEADBOLT_HERMES_SOCKET", "/run/deadbolt/ingress/hermes.sock")),
                   Path(os.environ.get("DEADBOLT_EXECUTOR_SOCKET", "/run/deadbolt/bot.sock")),
                   "hermes", *ids, token, dry_run)


class Relay:
    def __init__(self, config: BotConfig,
                 root_rpc: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]] = rpc):
        self.config = config
        self.root_rpc = root_rpc
        self.hermes_uid = pwd.getpwnam(config.hermes_user).pw_uid

    async def root(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self.root_rpc(str(self.config.executor_socket), payload)
        if not response.get("ok"):
            raise ProtocolError(str(response.get("error", "executor rejected request")))
        return response

    async def submit(self, message: dict[str, Any], uid: int) -> dict[str, Any]:
        if uid != self.hermes_uid:
            raise ProtocolError("unauthorized Unix peer")
        require_fields(message, {"op", "action", "profile", "reason"}, {"ttl_seconds", "hours"})
        if message["op"] != "submit":
            raise ProtocolError("Hermes may only submit requests")
        if message["action"] not in ("firewall_profile", "proxy_body_capture"):
            raise ProtocolError("Hermes action is not available")
        if any(not isinstance(message[key], str) for key in ("action", "profile", "reason")):
            raise ProtocolError("invalid request fields")
        payload = {"op": "create", "action": message["action"], "profile": message["profile"],
                   "reason": message["reason"], "requested_by_uid": uid}
        if "ttl_seconds" in message:
            payload["ttl_seconds"] = message["ttl_seconds"]
        if "hours" in message:
            payload["hours"] = message["hours"]
        return await self.root(payload)

    async def connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            sock = writer.get_extra_info("socket")
            if sock is None:
                raise ProtocolError("missing Unix peer")
            uid = peer_uid(sock)
            if uid != self.hermes_uid:
                raise ProtocolError("unauthorized Unix peer")
            result = await self.submit(await read_message(reader), uid)
        except (ProtocolError, ValueError, OSError) as exc:
            result = {"ok": False, "error": str(exc)}
        except Exception:
            LOG.exception("unexpected Hermes ingress error")
            result = {"ok": False, "error": "internal error"}
        try:
            await write_message(writer, result)
        except (OSError, ProtocolError):
            pass
        writer.close()
        await writer.wait_closed()

    async def list_all(self, state: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        while True:
            page = (await self.root({"op": "list", "state": state, "offset": len(rows)}))["requests"]
            rows.extend(page)
            if len(page) < 10:
                return rows

    async def mark_posted(self, request_id: str, message_id: str) -> dict[str, Any]:
        return (await self.root({"op": "posted", "request_id": request_id, "message_id": message_id}))["request"]

    async def status(self, request_id: str) -> dict[str, Any]:
        return (await self.root({"op": "status", "request_id": request_id}))["request"]

    async def capture_operator(self, operation: str, interaction_id: str, user_id: str,
                               guild_id: str, channel_id: str) -> dict[str, Any]:
        if operation not in ("capture_status", "capture_disable"):
            raise ProtocolError("invalid capture operation")
        return (await self.root({"op": operation, "interaction_id": interaction_id,
                                 "user_id": user_id, "guild_id": guild_id,
                                 "channel_id": channel_id}))["capture"]

    async def request_exclusion(self, operation: str, hostname: str, interaction_id: str,
                                user_id: str, guild_id: str, channel_id: str) -> dict[str, Any]:
        if operation not in ("add", "remove"):
            raise ProtocolError("invalid exclusion operation")
        return (await self.root({"op": "exclusion_create", "operation": operation,
                                 "hostname": hostname, "interaction_id": interaction_id,
                                 "user_id": user_id, "guild_id": guild_id,
                                 "channel_id": channel_id}))["request"]

    async def emergency_operator(self, operation: str, interaction_id: str, user_id: str,
                                 guild_id: str, channel_id: str) -> dict[str, Any]:
        if operation not in ("emergency_status", "emergency_stop", "emergency_recover_create"):
            raise ProtocolError("invalid emergency operation")
        response = await self.root({"op": operation, "interaction_id": interaction_id,
                                    "user_id": user_id, "guild_id": guild_id,
                                    "channel_id": channel_id})
        return response["request"] if operation == "emergency_recover_create" else response["emergency"]

    async def decide(self, row: dict[str, Any], decision: str, interaction_id: str,
                     user_id: str, guild_id: str, channel_id: str) -> dict[str, Any]:
        return (await self.root({"op": "decide", "request_id": row["id"], "decision": decision,
                                 "nonce": row["nonce"], "canonical_hash": row["canonical_hash"],
                                 "user_id": user_id, "guild_id": guild_id, "channel_id": channel_id,
                                 "message_id": row["posted_message_id"],
                                 "interaction_id": interaction_id}))["request"]

    async def decide_posted(self, card: dict[str, Any], decision: str, message_id: str,
                            interaction_id: str, user_id: str, guild_id: str,
                            channel_id: str) -> dict[str, Any]:
        # A view is created before Discord assigns the message ID. Fetch the
        # posted record at click time so its decision uses the actual ID.
        rows = await self.list_all("posted")
        current = next((row for row in rows if row["id"] == card["id"]), None)
        if (current is None or current["posted_message_id"] != message_id
                or current["nonce"] != card["nonce"]
                or current["canonical_hash"] != card["canonical_hash"]):
            raise ProtocolError("approval card no longer matches posted request")
        return await self.decide(current, decision, interaction_id, user_id, guild_id, channel_id)

    async def serve_ingress(self) -> asyncio.AbstractServer:
        if os.geteuid() == 0 or pwd.getpwuid(os.geteuid()).pw_name != "deadbolt":
            raise RuntimeError("bot must run as dedicated non-root deadbolt user")
        parent = self.config.hermes_socket.parent
        info = parent.stat()
        hermes_gid = pwd.getpwnam(self.config.hermes_user).pw_gid
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_gid != hermes_gid or info.st_mode & 0o777 != 0o750):
            raise RuntimeError("unsafe Hermes ingress directory")
        if self.config.hermes_socket.exists():
            old = self.config.hermes_socket.lstat()
            if not stat.S_ISSOCK(old.st_mode) or old.st_uid != os.geteuid():
                raise RuntimeError("unsafe existing Hermes ingress socket")
            self.config.hermes_socket.unlink()
        server = await asyncio.start_unix_server(self.connection, str(self.config.hermes_socket),
                                                 limit=MAX_MESSAGE_BYTES + 1)
        # Hermes traverses only its group-readable parent. The socket is
        # world-connectable *inside* that private directory; SO_PEERCRED still
        # checks the actual UID before reading a request.
        os.chmod(self.config.hermes_socket, 0o666)
        return server


class DryRunPoster:
    def __init__(self):
        self.next_id = int(time.time() * 1000)

    async def post(self, row: dict[str, Any]) -> str:
        self.next_id += 1
        print(f"Deadbolt dry run request {row['id']} (expires {row['pending_until']}):\n{row['description']}", flush=True)
        return str(self.next_id)


async def poll_pending(relay: Relay, post: Callable[[dict[str, Any]], Awaitable[str]]) -> None:
    while True:
        try:
            for row in await relay.list_all("pending"):
                message_id = await post(row)
                await relay.mark_posted(row["id"], message_id)
        except Exception:
            LOG.exception("approval polling failed")
        await asyncio.sleep(5)


async def handle_approval_button(relay: Relay, card_row: dict[str, Any], interaction: Any,
                                 decision: str, allowed: Callable[[Any], bool],
                                 render_card: Callable[[dict[str, Any]], Any]) -> None:
    """Handle a Discord button using the posted record, without needing a live Gateway in tests."""
    if not allowed(interaction) or not interaction.message:
        await interaction.response.send_message("Not authorized for this approval.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        updated = await relay.decide_posted(
            card_row, decision, str(interaction.message.id), str(interaction.id),
            str(interaction.user.id), str(interaction.guild_id), str(interaction.channel_id))
    except Exception as exc:
        await interaction.followup.send(f"Decision rejected: {exc}", ephemeral=True)
        return
    try:
        await interaction.message.edit(embed=render_card(updated), view=None)
    except Exception:
        LOG.exception("approval card update failed after executor decision")
        await interaction.followup.send(
            f"Request {updated['id']}: {updated['status']}. Card update failed; use /deadbolt status.",
            ephemeral=True)
        return
    await interaction.followup.send(f"Request {updated['id']}: {updated['status']}", ephemeral=True)


async def run_dry(config: BotConfig) -> None:
    relay = Relay(config)
    server = await relay.serve_ingress()
    poster = DryRunPoster()
    async with server:
        await asyncio.gather(server.serve_forever(), poll_pending(relay, poster.post))


async def run_discord(config: BotConfig) -> None:
    try:
        import discord
        from discord import app_commands
        from discord.ext import commands
    except ImportError as exc:
        raise RuntimeError("install Deadbolt with the 'bot' extra to use Discord") from exc

    relay = Relay(config)
    intents = discord.Intents.default()
    bot = commands.Bot(command_prefix=commands.when_mentioned, intents=intents)
    guild = discord.Object(id=int(config.guild_id))
    ready = asyncio.Event()

    def allowed(interaction: discord.Interaction) -> bool:
        return (str(interaction.user.id) == config.user_id and
                str(interaction.guild_id) == config.guild_id and
                str(interaction.channel_id) == config.channel_id)

    def card(row: dict[str, Any]) -> discord.Embed:
        description = discord.utils.escape_markdown(row["description"])
        embed = discord.Embed(title=f"Deadbolt request {row['id']}", description=description)
        embed.add_field(name="Status", value=row["status"])
        embed.add_field(name="Approval expires", value=f"<t:{int(row['pending_until'])}:F>")
        if row.get("last_error"):
            embed.add_field(name="Executor error", value=discord.utils.escape_markdown(row["last_error"]))
        return embed

    def view_for(row: dict[str, Any]) -> discord.ui.View:
        view = discord.ui.View(timeout=None)
        for decision in ("approve", "deny"):
            button = discord.ui.Button(label=decision.capitalize(),
                style=discord.ButtonStyle.success if decision == "approve" else discord.ButtonStyle.danger,
                custom_id=f"deadbolt:{decision}:{row['id']}:{row['nonce']}")

            async def callback(interaction: discord.Interaction, choice: str = decision) -> None:
                await handle_approval_button(relay, row, interaction, choice, allowed, card)

            button.callback = callback
            view.add_item(button)
        return view

    group = app_commands.Group(name="deadbolt", description="Deadbolt approval commands")

    @group.command(name="status", description="Show a Deadbolt request status")
    async def status_cmd(interaction: discord.Interaction, request_id: str) -> None:
        if not allowed(interaction):
            await interaction.response.send_message("Not authorized.", ephemeral=True)
            return
        try:
            row = await relay.status(request_id)
            await interaction.response.send_message(embed=card(row), ephemeral=True,
                                                    allowed_mentions=discord.AllowedMentions.none())
        except Exception as exc:
            await interaction.response.send_message(f"Status unavailable: {exc}", ephemeral=True)

    @group.command(name="deny", description="Deny a pending Deadbolt request")
    async def deny_cmd(interaction: discord.Interaction, request_id: str) -> None:
        if not allowed(interaction):
            await interaction.response.send_message("Not authorized.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            rows = await relay.list_all("posted")
            row = next((item for item in rows if item["id"] == request_id), None)
            if row is None:
                raise ProtocolError("request is not awaiting approval")
            updated = await relay.decide(row, "deny", str(interaction.id), str(interaction.user.id),
                                         str(interaction.guild_id), str(interaction.channel_id))
        except Exception as exc:
            await interaction.followup.send(f"Denial rejected: {exc}", ephemeral=True)
            return
        try:
            channel = bot.get_channel(int(config.channel_id)) or await bot.fetch_channel(int(config.channel_id))
            message = await channel.fetch_message(int(row["posted_message_id"]))
            await message.edit(embed=card(updated), view=None)
        except Exception:
            LOG.exception("approval card update failed after denial")
            await interaction.followup.send(
                f"Request {request_id}: denied. Card update failed; use /deadbolt status.", ephemeral=True)
            return
        await interaction.followup.send(f"Request {request_id}: denied", ephemeral=True)

    async def capture_command(interaction: discord.Interaction, operation: str) -> None:
        if not allowed(interaction):
            await interaction.response.send_message("Not authorized.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            result = await relay.capture_operator(operation, str(interaction.id),
                str(interaction.user.id), str(interaction.guild_id), str(interaction.channel_id))
            expiry = result["expires_at"] or "none"
            await interaction.followup.send(
                f"Body capture: {'enabled' if result['enabled'] else 'disabled'}; "
                f"expiry: {expiry}; outcome: {result['outcome']}", ephemeral=True,
                allowed_mentions=discord.AllowedMentions.none())
        except Exception as exc:
            await interaction.followup.send(f"Capture command failed: {exc}", ephemeral=True)

    @group.command(name="capture_status", description="Show authoritative body capture status")
    async def capture_status_cmd(interaction: discord.Interaction) -> None:
        await capture_command(interaction, "capture_status")

    @group.command(name="capture_disable", description="Disable body capture now")
    async def capture_disable_cmd(interaction: discord.Interaction) -> None:
        await capture_command(interaction, "capture_disable")

    async def exclusion_command(interaction: discord.Interaction, operation: str,
                                hostname: str) -> None:
        if not allowed(interaction):
            await interaction.response.send_message("Not authorized.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            row = await relay.request_exclusion(operation, hostname, str(interaction.id),
                str(interaction.user.id), str(interaction.guild_id), str(interaction.channel_id))
            await interaction.followup.send(
                f"Exclusion {operation} request {row['id']} queued for a separate approval card.",
                ephemeral=True, allowed_mentions=discord.AllowedMentions.none())
        except Exception as exc:
            await interaction.followup.send(f"Exclusion request rejected: {exc}", ephemeral=True)

    @group.command(name="exclusion_add", description="Request an exact-host body exclusion")
    async def exclusion_add_cmd(interaction: discord.Interaction, hostname: str) -> None:
        await exclusion_command(interaction, "add", hostname)

    @group.command(name="exclusion_remove", description="Request removal of a body exclusion")
    async def exclusion_remove_cmd(interaction: discord.Interaction, hostname: str) -> None:
        await exclusion_command(interaction, "remove", hostname)

    async def emergency_command(interaction: discord.Interaction, operation: str) -> None:
        if not allowed(interaction):
            await interaction.response.send_message("Not authorized.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            result = await relay.emergency_operator(operation, str(interaction.id),
                str(interaction.user.id), str(interaction.guild_id), str(interaction.channel_id))
            if operation == "emergency_recover_create":
                message = f"Recovery request {result['id']} queued for a separate approval card."
            else:
                message = (f"Emergency switch: {result['state']}; Hermes direct-egress block: "
                           f"{'enforced' if result['egress_block_enforced'] else 'absent'}; "
                           f"running watched units: {', '.join(result['running_units']) or 'none'}; "
                           f"generation: {result['generation']}.")
            await interaction.followup.send(message, ephemeral=True,
                                            allowed_mentions=discord.AllowedMentions.none())
        except Exception as exc:
            await interaction.followup.send(f"Emergency command failed: {exc}", ephemeral=True)

    @group.command(name="emergency_status", description="Show Hermes emergency switch status")
    async def emergency_status_cmd(interaction: discord.Interaction) -> None:
        await emergency_command(interaction, "emergency_status")

    @group.command(name="emergency_stop", description="Stop Hermes proxy and block Hermes direct egress")
    async def emergency_stop_cmd(interaction: discord.Interaction) -> None:
        await emergency_command(interaction, "emergency_stop")

    @group.command(name="emergency_recover", description="Request separately approved Hermes recovery")
    async def emergency_recover_cmd(interaction: discord.Interaction) -> None:
        await emergency_command(interaction, "emergency_recover_create")

    bot.tree.add_command(group, guild=guild)

    @bot.event
    async def on_ready() -> None:
        if not ready.is_set():
            for row in await relay.list_all("posted"):
                bot.add_view(view_for(row), message_id=int(row["posted_message_id"]))
            await bot.tree.sync(guild=guild)
            ready.set()
        LOG.info("Discord relay ready")

    async def post(row: dict[str, Any]) -> str:
        await ready.wait()
        channel = bot.get_channel(int(config.channel_id)) or await bot.fetch_channel(int(config.channel_id))
        message = await channel.send(embed=card(row), view=view_for(row),
                                     allowed_mentions=discord.AllowedMentions.none())
        return str(message.id)

    server = await relay.serve_ingress()
    async with server:
        await asyncio.gather(server.serve_forever(), poll_pending(relay, post), bot.start(config.token or ""))


def main() -> None:
    parser = argparse.ArgumentParser(description="Deadbolt unprivileged Discord relay")
    parser.add_argument("--dry-run", action="store_true", help="post cards to stdout without a Discord token")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    config = BotConfig.environment(args.dry_run)
    asyncio.run(run_dry(config) if args.dry_run else run_discord(config))


if __name__ == "__main__":
    main()
