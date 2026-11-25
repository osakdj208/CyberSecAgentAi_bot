"""Deep Telegram resolver (MTProto) — optional enrichment for the public
Telegram card (catalogue item W8, deep tier).

A DEDICATED Telegram account session (Telethon StringSession) resolves a
public @username to what the Bot API can never expose: the numeric ID,
Telegram's own verified / scam / fake flags, profile-photo count, the
full about text, a channel's participant count and its linked discussion
group. Public data only — phone numbers are never read or returned.

Configuration comes from the environment:
  TG_API_ID, TG_API_HASH, TG_SESSION
If any value is missing, or telethon is not installed, deep lookup is
disabled and the bot silently falls back to the public card. The session
is a full-access credential: it is read from the environment only, never
logged, never returned, and never written anywhere by this module.

Flood safety: lookups are serialized and paced (MIN_INTERVAL), because
Telegram rate-limits username resolution and restricts accounts that
burst. One lookup builds one short-lived client on its own event loop,
which keeps it safe to call from the bot's synchronous threads.
"""
import asyncio
import os
import threading
import time

MIN_INTERVAL = 3.0  # seconds between resolves (flood safety)

_lock = threading.Lock()
_last_call = 0.0


def configured() -> bool:
    return bool(os.environ.get("TG_API_ID") and os.environ.get("TG_API_HASH")
                and os.environ.get("TG_SESSION"))


async def _resolve_async(query):
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.tl.functions.channels import GetFullChannelRequest
    from telethon.tl.functions.users import GetFullUserRequest
    from telethon.tl.types import Channel, Chat, User

    kind, value = query
    client = TelegramClient(
        StringSession(os.environ["TG_SESSION"]),
        int(os.environ["TG_API_ID"]),
        os.environ["TG_API_HASH"])
    await client.connect()
    try:
        if not await client.is_user_authorized():
            return {"error": "session_not_authorized"}
        ref = f"@{value}" if kind == "username" else value
        entity = await client.get_entity(ref)
        info = {"id": entity.id,
                "username": getattr(entity, "username", None),
                "verified": bool(getattr(entity, "verified", False)),
                "scam": bool(getattr(entity, "scam", False)),
                "fake": bool(getattr(entity, "fake", False))}
        if isinstance(entity, User):
            info["kind"] = "bot" if entity.bot else "user"
            info["is_bot"] = bool(entity.bot)
            info["name"] = " ".join(
                x for x in [entity.first_name, entity.last_name] if x) or None
            full = await client(GetFullUserRequest(entity))
            info["about"] = getattr(full.full_user, "about", None)
            photos = await client.get_profile_photos(entity, limit=0)
            total = getattr(photos, "total", None)
            info["photos"] = total if total is not None else len(photos)
        elif isinstance(entity, Channel):
            info["kind"] = "supergroup" if entity.megagroup else "channel"
            info["is_bot"] = False
            info["name"] = entity.title
            info["marked_id"] = int(f"-100{entity.id}")
            full = await client(GetFullChannelRequest(entity))
            info["about"] = getattr(full.full_chat, "about", None)
            info["participants"] = getattr(
                full.full_chat, "participants_count", None)
            linked_id = getattr(full.full_chat, "linked_chat_id", None)
            if linked_id:
                try:
                    linked = await client.get_entity(linked_id)
                    info["linked_username"] = getattr(linked, "username", None)
                    info["linked_title"] = getattr(linked, "title", None)
                except Exception:
                    pass
        elif isinstance(entity, Chat):
            info["kind"] = "group"
            info["is_bot"] = False
            info["name"] = entity.title
            info["marked_id"] = -entity.id
            info["participants"] = getattr(entity, "participants_count", None)
        else:
            info["kind"] = "unknown"
        return info
    finally:
        await client.disconnect()


async def _phone_async(phone):
    """Resolve a phone number to its PUBLIC Telegram profile, using the
    platform's own contact-discovery mechanism. Telegram only returns a
    user when the number's owner allows being found by number; otherwise
    the import comes back empty — the owner's privacy setting decides.
    The imported contact is deleted again immediately; the dedicated
    account keeps no address book. The number itself is never returned
    (the caller already has it — they typed it)."""
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.tl.functions.contacts import (DeleteContactsRequest,
                                                ImportContactsRequest)
    from telethon.tl.types import InputPhoneContact

    client = TelegramClient(
        StringSession(os.environ["TG_SESSION"]),
        int(os.environ["TG_API_ID"]),
        os.environ["TG_API_HASH"])
    await client.connect()
    try:
        if not await client.is_user_authorized():
            return {"error": "session_not_authorized"}
        result = await client(ImportContactsRequest(
            [InputPhoneContact(client_id=1, phone=phone,
                               first_name="Card", last_name="")]))
        users = list(getattr(result, "users", []) or [])
        if not users:
            return {"found": False}
        user = users[0]
        info = {"found": True,
                "id": user.id,
                "username": getattr(user, "username", None),
                "is_bot": bool(getattr(user, "bot", False)),
                "verified": bool(getattr(user, "verified", False)),
                "scam": bool(getattr(user, "scam", False)),
                "fake": bool(getattr(user, "fake", False)),
                "name": " ".join(
                    x for x in [getattr(user, "first_name", None),
                                getattr(user, "last_name", None)] if x) or None}
        try:
            await client(DeleteContactsRequest([user]))
        except Exception:
            pass
        return info
    finally:
        await client.disconnect()


def phone_lookup(phone):
    """Phone -> public Telegram profile (or {"found": False}). Same
    contract as deep_lookup: None when not configured, in-band errors."""
    if not configured():
        return None
    global _last_call
    with _lock:
        wait = MIN_INTERVAL - (time.time() - _last_call)
        if wait > 0:
            time.sleep(wait)
        try:
            result = asyncio.run(_phone_async(phone))
        except Exception as exc:  # telethon errors included
            name = type(exc).__name__
            if "FloodWait" in name:
                result = {"error": "flood"}
            else:
                result = {"error": name}
        _last_call = time.time()
        return result


def deep_lookup(query):
    """Resolve a parsed card query via MTProto. Returns a dict, or None
    when deep lookup is not configured. Errors are reported in-band as
    {"error": <name>} so the caller can degrade to the public card."""
    if not configured():
        return None
    global _last_call
    with _lock:
        wait = MIN_INTERVAL - (time.time() - _last_call)
        if wait > 0:
            time.sleep(wait)
        try:
            result = asyncio.run(_resolve_async(query))
        except Exception as exc:  # telethon errors included
            name = type(exc).__name__
            if "FloodWait" in name:
                result = {"error": "flood"}
            elif "UsernameNotOccupied" in name or "UsernameInvalid" in name:
                result = {"error": "not_found"}
            else:
                result = {"error": name}
        _last_call = time.time()
        return result
