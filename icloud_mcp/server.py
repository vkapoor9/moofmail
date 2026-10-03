"""iCloud MCP MCP server — FastMCP entry point wiring every v1 tool.

Read is read-only. Send + delete are gated. Secret comes from Keychain.
Run: `python -m icloud_mcp.server` (stdio), or register with `claude mcp add`.

Config is loaded lazily on first tool use so the server can start (and be
registered/introspected) even before credentials are set up.
"""
from __future__ import annotations

import fnmatch
import functools
import inspect
import json
import os
import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from .auditsum import AUDIT_PATH
from .config import Config, Accounts, load_accounts, ConfigError, resolve_timezone
from .caldav import (CalDavClient, build_vevent, update_vevent_lines, _fmt_dt,
                      has_recurrence, has_attendees)
from .carddav import CardDavClient, na_tels
from .imap_read import MailReader
from .smtp_send import MailSender, reply_recipients
from .keychain import has_password
from .triage import rank_inbox, format_brief
from .unsubscribe import parse_unsubscribe, execute_one_click
from .rules import plan_cleanup
from . import cleanup as _cleanup

log = logging.getLogger("icloud_mcp")
mcp = FastMCP("iCloud MCP")

# ---- audit log ----
_AUDIT = AUDIT_PATH  # single definition, shared with the brief's reader


def _audit(action: str, detail: str) -> None:
    try:
        os.makedirs(os.path.dirname(_AUDIT), exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        with open(_AUDIT, "a") as f:
            f.write(f"{ts}\t{action}\t{detail}\n")
    except OSError:
        pass  # never let audit failure break a tool


# ---- lazy singletons ----
_state: dict = {}


def _accounts() -> Accounts:
    if "accounts" not in _state:
        _state["accounts"] = load_accounts()
    return _state["accounts"]


def _cfg(account: str | None = None, service: str | None = None) -> Config:
    """Config for one account (the default account when `account` is None).

    `service` routes calendar/contacts to the account configured to hold them,
    which need not be the default MAIL account.
    """
    return _accounts().get(account, service=service)


def _one(account: str | None = None, service: str | None = None) -> Config:
    """Resolve a WRITE to exactly one account. Refuses account="all"."""
    return _accounts().require_one(account, service=service)


def _serves(accts: Accounts, service: str) -> str:
    """Which account(s) a service reads, for `status`.

    Reports "all (a, b)" when an unpinned service spans every account, because
    naming a single account would be a lie there and this line exists specifically so the
    silent-wrong-account bug class is inspectable rather than invisible.
    """
    if accts.spans_all(service=service):
        return f"all ({', '.join(accts.names)})"
    return accts.get(service=service).name


def _reader(account: str | None = None) -> MailReader:
    cfg = _cfg(account)
    readers = _state.setdefault("readers", {})
    if cfg.name not in readers:
        readers[cfg.name] = MailReader(cfg)
    return readers[cfg.name]


def _sender(account: str | None = None) -> MailSender:
    cfg = _cfg(account)
    senders = _state.setdefault("senders", {})
    if cfg.name not in senders:
        senders[cfg.name] = MailSender(cfg)
    return senders[cfg.name]


def _carddav(cfg: Config) -> CardDavClient:
    """CardDAV client for an ALREADY RESOLVED account.

    Takes a Config rather than a name so a fan-out loop cannot accidentally
    re-resolve and land back on the default account.
    """
    clients = _state.setdefault("carddav", {})
    if cfg.name not in clients:
        clients[cfg.name] = CardDavClient(cfg)
    return clients[cfg.name]


def _caldav(cfg: Config) -> CalDavClient:
    """CalDAV client for an ALREADY RESOLVED account (see _carddav)."""
    clients = _state.setdefault("caldav", {})
    if cfg.name not in clients:
        clients[cfg.name] = CalDavClient(cfg)
    return clients[cfg.name]


def _local_tz(cfg) -> ZoneInfo:
    """The calendar zone; unset or invalid means the machine's local zone."""
    return resolve_timezone(cfg.calendar_timezone)


def _day_window(day: str, tz: ZoneInfo) -> tuple[datetime, datetime]:
    """Resolve today/tomorrow/week into a concrete local window."""
    start = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    d = (day or "today").strip().lower()
    if d == "tomorrow":
        start += timedelta(days=1)
        return start, start + timedelta(days=1)
    if d in ("week", "7d"):
        return start, start + timedelta(days=7)
    if d == "today":
        return start, start + timedelta(days=1)
    raise ToolError(f"day must be today, tomorrow or week (got {day!r})")


def _fanout(account: str | None, service: str | None = None) -> list[Config]:
    """Accounts a READ tool should cover. `account="all"` spans every account."""
    return _accounts().fanout(account, service=service)


# ---------------- confidential folders: never read, on ANY surface ----------
#: Apple stores iCloud Notes as ordinary IMAP folders, so "access to mail"
#: silently included them. Note bodies are treated as confidential and must
#: never reach a model context. Every client of this server (and any remote
#: transport, if one is added) feeds a model context, so this is enforced
#: HERE, in the shared server, not on one surface. Ordinary mail folders stay open by
#: design; only Notes is confidential.
DEFAULT_BLOCKED_FOLDERS: tuple[str, ...] = ("Notes", "Notes/*")


def _blocked_patterns() -> tuple[str, ...]:
    if "blocked_folders" not in _state:
        pats = DEFAULT_BLOCKED_FOLDERS
        try:
            import tomllib
            from pathlib import Path
            from .config import DEFAULT_PATH
            f = Path(os.path.expanduser(DEFAULT_PATH))
            if f.exists():
                with f.open("rb") as fh:
                    got = (tomllib.load(fh).get("privacy") or {}).get("blocked_folders")
                if got is not None:
                    pats = tuple(got)
        except Exception:  # noqa: BLE001 - a bad config must not UNBLOCK anything
            pats = DEFAULT_BLOCKED_FOLDERS
        _state["blocked_folders"] = pats
    return _state["blocked_folders"]


def folder_blocked(folder: str) -> bool:
    """Whole-name fnmatch, case-insensitive, so 'Notes' never blocks 'Notestalgia'."""
    name = (folder or "").strip().lower()
    return any(fnmatch.fnmatch(name, p.strip().lower()) for p in _blocked_patterns())


def _check_folders(sig, args, kwargs, tool: str = "") -> None:
    """Refuse a blocked folder BEFORE the wrapped tool runs, so nothing opens it.

    Reads the bound arguments rather than a hardcoded list of tools, so a tool
    added later is covered without anyone remembering to wire it up. Both
    `folder` and `dest_folder` are checked: reading out of Notes and filing mail
    into Notes are each refused.
    """
    try:
        bound = sig.bind_partial(*args, **kwargs)
    except TypeError:
        return  # a genuine call error; let the real call raise it
    for key in ("folder", "dest_folder"):
        val = bound.arguments.get(key)
        if isinstance(val, str) and folder_blocked(val):
            # Logged because a refused Notes read is exactly what an injected
            # instruction would attempt; the brief surfaces these.
            _audit("blocked_folder", f"{tool} {key}={val!r}")
            raise ToolError(
                f"folder {val!r} is not available. iCloud Notes are treated as "
                "confidential and are never read by this server."
            )


def _guard(fn):
    """Wrap a tool so config/keychain errors return a clear message, not a stack trace.

    Uses functools.wraps so FastMCP introspects the ORIGINAL signature (via
    __wrapped__) when building each tool's argument schema.
    """
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*a, **k):
        # Outside the try on purpose: a blocked folder is a refusal, not an
        # internal error, and must not be re-wrapped by the handler below.
        _check_folders(sig, a, k, fn.__name__)
        try:
            return fn(*a, **k)
        except ConfigError as e:
            raise ToolError(str(e)) from e
        except Exception as e:  # noqa: BLE001
            log.exception("tool %s failed", fn.__name__)
            raise ToolError(f"{type(e).__name__}: {e}") from e
    return wrapper


# ===================== READ =====================
@mcp.tool(title="Connection status",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def status() -> dict:
    """Health check: config + Keychain credential state for EVERY configured account."""
    try:
        accts = _accounts()
    except ConfigError as e:
        return {"config": False, "detail": str(e)}
    rows = []
    for cfg in accts.all():
        rows.append({
            "account": cfg.name,
            "address": cfg.address,
            "default": cfg.name == accts.default_name,
            "keychain_credential_set": has_password(cfg.keychain_account, cfg.keychain_service),
            "keychain_service": cfg.keychain_service,
            "send_enabled": cfg.send_enabled,
        })
    return {
        "config": True,
        "default_account": accts.default_name,
        # Which account each service actually reads. Calendar and contacts can be
        # pinned elsewhere, and when they silently were not, searches came back
        # empty in a way indistinguishable from "no such contact".
        "serves": {
            "mail": accts.default_name,
            "calendar": _serves(accts, "calendar"),
            "contacts": _serves(accts, "contacts"),
        },
        "accounts": rows,
        "read_window_days": accts.get().window_days,
        "note": "If keychain_credential_set is false for an account, add its app-specific "
                "password: security add-generic-password -s <service> -a <user> -w",
    }


@mcp.tool(title="List messages",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def list_inbox(folder: str = "INBOX", since_days: int | None = None, limit: int | None = None,
               account: str | None = None) -> list[dict]:
    """List newest-first message summaries from a folder (read-only).

    account: account name, or "all" to span every configured account.
    """
    out = []
    for cfg in _fanout(account):
        for m in _reader(cfg.name).list_inbox(folder=folder, since_days=since_days, limit=limit):
            d = m.to_summary(); d["account"] = cfg.name
            out.append(d)
    _audit("list_inbox", f"{folder} account={account or 'default'} n={len(out)}")
    return out


@mcp.tool(title="Search mail",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def search_mail(query: str, folder: str = "INBOX", limit: int | None = None,
                account: str | None = None) -> list[dict]:
    """Search subject/from/body for text (read-only). account="all" spans all accounts."""
    out = []
    for cfg in _fanout(account):
        for m in _reader(cfg.name).search_mail(query, folder=folder, limit=limit):
            d = m.to_summary(); d["account"] = cfg.name
            out.append(d)
    _audit("search_mail", f"q={query!r} account={account or 'default'} n={len(out)}")
    return out


@mcp.tool(title="Read a message",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def get_message(uid: int, folder: str = "INBOX", account: str | None = None) -> dict:
    """Fetch a full message (body + attachment names). Never marks it read."""
    m = _reader(account).get_message(uid, folder=folder)
    if m is None:
        return {"error": "not_found", "detail": f"uid {uid} not in {folder}"}
    _audit("get_message", f"{folder}#{uid}")
    d = m.to_summary()
    d["body_text"] = m.body_text
    d["attachments"] = m.attachments
    return d


def _folder_names(account: str | None = None) -> list[str]:
    """Raw folder list from IMAP. Split out so the blocking filter is testable."""
    return _reader(account).list_folders()


@mcp.tool(title="List mail folders",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def list_folders(account: str | None = None) -> list[str]:
    """List mailbox folders (read-only). Confidential folders are omitted.

    Hiding is not the control - _check_folders is, because `folder` is free text.
    This just keeps the model from seeing a name it will only be refused on.
    """
    return [f for f in _folder_names(account) if not folder_blocked(f)]


# ===================== TRIAGE =====================
@mcp.tool(title="Triage inbox",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def triage_inbox(window_days: int | None = None, account: str | None = None) -> list[dict]:
    """Rank real/personal mail by importance (bulk excluded by default). Read-only.

    account="all" merges every inbox into one ranking, highest score first.
    """
    rows = []
    for cfg in _fanout(account):
        msgs = _reader(cfg.name).list_inbox(since_days=window_days)
        for (m, s, r) in rank_inbox(msgs, cfg):
            rows.append({**m.to_summary(), "score": s, "reason": r, "account": cfg.name})
    rows.sort(key=lambda d: d["score"], reverse=True)
    _audit("triage_inbox", f"account={account or 'default'} n={len(rows)}")
    return rows


@mcp.tool(title="Morning brief",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def morning_brief(window_days: int | None = None, account: str | None = None) -> dict:
    """Build the morning-brief digest (plain text). Read-only.

    account="all" builds one brief spanning every configured inbox.
    """
    ranked = []
    for cfg in _fanout(account):
        msgs = _reader(cfg.name).list_inbox(since_days=window_days)
        ranked.extend(rank_inbox(msgs, cfg))
    ranked.sort(key=lambda t: t[1], reverse=True)
    text = format_brief(ranked)
    _audit("morning_brief", f"account={account or 'default'} items={len(ranked)}")
    return {"text": text, "count": len(ranked)}


# ===================== CALENDAR =====================
@mcp.tool(title="List calendars",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def list_calendars(account: str | None = None) -> list[dict]:
    """List calendars. `in_brief` marks the ones feeding the morning brief.

    Reads the account set by [calendar].account. account="all" spans them all.
    """
    out = []
    for cfg in _fanout(account, service="calendar"):
        keep = {n.strip().lower() for n in cfg.calendar_include}
        out += [{"name": c.name, "account": cfg.name,
                 "in_brief": (not keep) or c.name.strip().lower() in keep}
                for c in _caldav(cfg).calendars()]
    return out


@mcp.tool(title="List calendar events",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def list_events(start: str, end: str, calendar: str | None = None,
                account: str | None = None) -> list[dict]:
    """Events between two ISO datetimes/dates (read-only).

    Recurring events arrive already expanded into concrete instances.
    `calendar` limits to one by name; omit it to use the configured set.
    Reads the account set by [calendar].account. account="all" spans them all.
    """
    out = []
    for cfg in _fanout(account, service="calendar"):
        tz = _local_tz(cfg)
        def _iso(v: str, tz=tz) -> datetime:
            d = datetime.fromisoformat(v)
            return d if d.tzinfo else d.replace(tzinfo=tz)
        include = [calendar] if calendar else (cfg.calendar_include or None)
        for e in _caldav(cfg).events(_iso(start), _iso(end), include=include):
            d = e.to_dict(); d["account"] = cfg.name
            out.append(d)
    out.sort(key=lambda d: d["start"] or "")
    _audit("list_events", f"{start}..{end} cal={calendar or 'configured'} n={len(out)}")
    return out


@mcp.tool(title="Day agenda",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def agenda(day: str = "today", account: str | None = None) -> dict:
    """Schedule for today, tomorrow or the next week. Read-only.

    Reads the account set by [calendar].account. account="all" merges every
    account into one chronological list, tagging each event with its source.
    """
    cfgs = _fanout(account, service="calendar")
    tz = _local_tz(cfgs[0])
    start, end = _day_window(day, tz)
    pairs = [(cfg, e) for cfg in cfgs
             for e in _caldav(cfg).events(start, end, include=cfg.calendar_include or None)]
    # Merging accounts destroys the per-account ordering, so sort explicitly.
    timed = sorted((p for p in pairs if not p[1].all_day and p[1].start),
                   key=lambda p: p[1].start)
    allday = [p for p in pairs if p[1].all_day or not p[1].start]
    # Locations legitimately contain newlines (iCalendar \\n), which would break a
    # one-line agenda. Collapse for display only; the structured events keep them.
    def _flat(v: str) -> str:
        return " ".join((v or "").split())
    # Only name the account when more than one is in play, else it is noise.
    multi = len(cfgs) > 1
    def _tag(cfg) -> str:
        return f"  [{cfg.name}]" if multi else ""
    # Over a multi-day window bare clock times read as unsorted (4:45 PM on one
    # line, 1:00 PM on the next), so date-stamp each line. A single day needs no
    # prefix; repeating today's date on every line is noise.
    multiday = (end - start).days > 1
    def _when(v) -> str:
        if not multiday or v is None:
            return ""
        d = v.astimezone(tz) if isinstance(v, datetime) else v
        return d.strftime("%a %-m/%-d  ")
    def _title(e) -> str:
        return _flat(e.summary) or "(untitled)"
    lines = [_when(e.start) + f"{e.start.astimezone(tz).strftime('%-I:%M %p')}  {_title(e)}"
             + (f"  ({_flat(e.location)})" if e.location else "") + _tag(cfg)
             for cfg, e in timed]
    lines += [_when(e.start) + f"all day    {_title(e)}" + _tag(cfg) for cfg, e in allday]
    _audit("agenda", f"{day} account={account or 'configured'} n={len(pairs)}")
    return {"day": day, "count": len(pairs),
            "text": "\n".join(lines) or "Nothing scheduled.",
            "events": [{**e.to_dict(), "account": cfg.name} for cfg, e in timed + allday]}


@mcp.tool(title="Find free time",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def free_slots(day: str = "today", min_minutes: int = 30,
               work_start: int = 9, work_end: int = 18,
               account: str | None = None) -> list[dict]:
    """Open gaps between timed events inside working hours. Read-only.

    account="all" treats you as busy when ANY account has you booked, which is
    the only reading of "free" that survives having two calendars.
    """
    cfgs = _fanout(account, service="calendar")
    tz = _local_tz(cfgs[0])
    start, end = _day_window(day, tz)
    evs = [e for cfg in cfgs
           for e in _caldav(cfg).events(start, end, include=cfg.calendar_include or None)
           if not e.all_day and e.start and e.end]
    out = []
    for d in range((end - start).days or 1):
        day_start = (start + timedelta(days=d)).replace(hour=work_start)
        day_end = (start + timedelta(days=d)).replace(hour=work_end)
        busy = sorted(
            ((max(e.start.astimezone(tz), day_start), min(e.end.astimezone(tz), day_end))
             for e in evs
             if e.end.astimezone(tz) > day_start and e.start.astimezone(tz) < day_end),
            key=lambda t: t[0])
        cursor = day_start
        for b0, b1 in busy:
            if (b0 - cursor).total_seconds() >= min_minutes * 60:
                out.append({"start": cursor.isoformat(), "end": b0.isoformat()})
            cursor = max(cursor, b1)
        if (day_end - cursor).total_seconds() >= min_minutes * 60:
            out.append({"start": cursor.isoformat(), "end": day_end.isoformat()})
    return out


@mcp.tool(title="Create a calendar event",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True))
@_guard
def create_event(summary: str, start: str, end: str, calendar: str | None = None,
                 location: str = "", description: str = "", all_day: bool = False,
                 attendees: list[str] | None = None, confirm: bool = False,
                 account: str | None = None) -> dict:
    """Create a calendar event. Requires confirm=True.

    ATTENDEES MAKE ICLOUD SEND REAL INVITATION EMAILS. Every attendee therefore
    goes through the same learn-on-approve gate as send_mail before anything is
    written, rather than inventing a second policy for outbound mail that happens
    to be wearing a calendar costume.
    """
    cfg = _one(account, service="calendar")
    tz = _local_tz(cfg)
    people = [a.strip() for a in (attendees or []) if a and a.strip()]

    if not confirm:
        return {"created": False, "needs_confirmation": True,
                "detail": f"Would create {summary!r} on {start}."
                          + (f" Invitations would be emailed to: {', '.join(people)}."
                             if people else "")
                          + " Re-call with confirm=True."}

    if people:
        # Invitations are real outbound email, so sending must be switched on.
        if not cfg.send_enabled:
            return {"created": False, "needs_confirmation": False,
                    "detail": "Adding attendees emails them an invitation, and sending is "
                              "turned off for this account. Create the event without "
                              "attendees, or turn sending on first."}
        # The invitation is emailed by the CALENDAR's account, so it is that
        # account's trusted store that must have approved the attendees.
        sender = _sender(cfg.name)
        untrusted = [a for a in people if not sender.trusted.is_trusted(a.lower())]
        if untrusted:
            return {"created": False, "needs_confirmation": True,
                    "detail": f"{', '.join(untrusted)} would receive an invitation email but "
                              "are not trusted recipients. Send them mail first, or remove them."}

    def _iso(v: str):
        d = datetime.fromisoformat(v)
        if all_day:
            return d.date()
        return d if d.tzinfo else d.replace(tzinfo=tz)

    cals = _caldav(cfg).calendars()
    want = (calendar or cfg.calendar_write or "").strip().lower()
    target = next((c for c in cals if c.name.strip().lower() == want), None)
    if target is None:
        # Writes resolve to ONE account, so on a multi-account setup the calendar
        # may simply live on another one. Say so: without this the message reads
        # as "that calendar does not exist" when it plainly does.
        others = [n for n in _accounts().names if n != cfg.name]
        hint = (f" Searched account {cfg.name!r} only; also configured: "
                f"{', '.join(others)}. Pass account= to write to one of those."
                if others else "")
        raise ToolError(f"calendar {calendar or cfg.calendar_write!r} not found. "
                        f"Available: {', '.join(c.name for c in cals)}.{hint}")

    import uuid as _uuid
    uid = str(_uuid.uuid4()).upper()
    ics = build_vevent(summary, _iso(start), _iso(end), uid=uid, location=location,
                       description=description, all_day=all_day,
                       attendees=people, organizer=cfg.address if people else None)
    ok, detail = _caldav(cfg).put_event(target.href, uid, ics)
    _audit("create_event",
           f"{cfg.name}/{target.name} {summary!r} attendees={len(people)} ok={ok}")
    return {"created": ok, "needs_confirmation": False, "uid": uid,
            "calendar": target.name, "account": cfg.name, "detail": detail}


@mcp.tool(title="Edit a calendar event",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False))
@_guard
def update_event(uid: str, summary: str | None = None, start: str | None = None,
                 end: str | None = None, location: str | None = None,
                 all_day: bool = False, confirm: bool = False,
                 account: str | None = None) -> dict:
    """Change an existing event. Requires confirm=True.

    Edits the raw iCalendar in place rather than regenerating it, so recurrence
    rules, alarms and attendees are preserved. Refuses recurring series: changing
    a DTSTART there rewrites every occurrence, which is rarely what is meant.
    """
    cfg = _one(account, service="calendar")
    tz = _local_tz(cfg)
    client = _caldav(cfg)
    ev = client.find_by_uid(uid)
    if ev is None:
        raise ToolError(f"no event with uid {uid} within a year of today")

    ok, raw = client.get_raw(ev.href)
    if not ok:
        raise ToolError(f"could not fetch the event source for {uid}")
    if has_recurrence(raw):
        return {"updated": False, "detail":
                f"{ev.summary!r} is a recurring series. Editing it here would rewrite every "
                "occurrence. Change it in Calendar so you can choose this event or the series."}

    changes: dict = {}
    if summary is not None:
        from .caldav import _escape_text
        changes["SUMMARY"] = ("", _escape_text(summary))
    if location is not None:
        from .caldav import _escape_text
        changes["LOCATION"] = ("", _escape_text(location))
    def _iso(v: str):
        d = datetime.fromisoformat(v)
        return d.date() if all_day else (d if d.tzinfo else d.replace(tzinfo=tz))
    if start is not None:
        changes["DTSTART"] = _fmt_dt(_iso(start), all_day)
    if end is not None:
        changes["DTEND"] = _fmt_dt(_iso(end), all_day)
    if not changes:
        raise ToolError("nothing to change: pass summary, start, end or location")

    if not confirm:
        return {"updated": False, "needs_confirmation": True,
                "current": ev.to_dict(),
                "detail": f"Would change {', '.join(changes)} on {ev.summary!r}. "
                          "Re-call with confirm=True."}

    new_raw = update_vevent_lines(raw, changes)
    ok, detail = client.put_event(ev.href.rsplit("/", 1)[0], uid, new_raw, etag=ev.etag)
    _audit("update_event", f"{uid} fields={list(changes)} ok={ok}")
    return {"updated": ok, "uid": uid, "changed": list(changes), "detail": detail}


@mcp.tool(title="Delete a calendar event",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False))
@_guard
def delete_event(uid: str, confirm: bool = False, account: str | None = None) -> dict:
    """Delete an event. Requires confirm=True. IRREVERSIBLE.

    Unlike mail, where delete means move to Deleted Messages, CalDAV removal is
    immediate and there is no calendar Trash to recover from. Without confirm this
    returns the full event so you can see exactly what would go.

    Refuses events with attendees: deleting those sends cancellation emails to
    other people, which is outbound mail and belongs behind the send gate.
    """
    client = _caldav(_one(account, service="calendar"))
    ev = client.find_by_uid(uid)
    if ev is None:
        raise ToolError(f"no event with uid {uid} within a year of today")

    ok, raw = client.get_raw(ev.href)
    recurring = ok and has_recurrence(raw)
    invited = ok and has_attendees(raw)

    if invited:
        return {"deleted": False, "detail":
                f"{ev.summary!r} has attendees. Deleting it emails them a cancellation, "
                "so do that in Calendar where you can see who is affected."}

    if not confirm:
        return {"deleted": False, "needs_confirmation": True, "event": ev.to_dict(),
                "warning": ("This is a RECURRING series: deleting removes EVERY occurrence."
                            if recurring else
                            "This is permanent. Calendar has no Trash to restore from."),
                "detail": "Re-call with confirm=True."}

    ok, detail = client.delete_event(ev.href, etag=ev.etag)
    _audit("delete_event", f"{uid} {ev.summary!r} recurring={recurring} ok={ok}")
    return {"deleted": ok, "uid": uid, "summary": ev.summary, "detail": detail}


# ===================== CONTACTS (read-only) =====================
def _matches(query: str, haystack: str) -> bool:
    """True when the whole query, or every word of it, appears in `haystack`.

    Contiguous matching alone fails on "Jane Doe" against a card that reads
    "Jane Q. Doe": it returns nobody, which is indistinguishable from the
    person not existing. Requiring EVERY token still keeps "Jane Smith" from
    matching her, so this widens recall without inventing matches.
    """
    q = " ".join((query or "").lower().split())
    hay = (haystack or "").lower()
    if q and q in hay:
        return True
    parts = q.split()
    return len(parts) > 1 and all(p in hay for p in parts)


def _contact_summary(v) -> dict:
    return {
        "name": v.fn,
        "org": v.org,
        "emails": v.emails,
        "phones": v.tels,
        "north_american_phones": na_tels(v),
        "uid": v.uid,
    }


@mcp.tool(title="Search contacts",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def search_contacts(query: str, limit: int = 20, account: str | None = None) -> list[dict]:
    """Search Contacts by name, company, email, or phone digits (read-only).

    Phone matching compares digits only, so "2125550142" finds "(212) 555-0142".
    Reads the account set by [contacts].account. account="all" spans them all.
    """
    q = (query or "").strip().lower()
    if not q:
        raise ToolError("query is required")
    qdigits = "".join(ch for ch in q if ch.isdigit())
    out = []
    for cfg in _fanout(account, service="contacts"):
        for v in _carddav(cfg).fetch_all():
            if v.is_group:
                continue
            hay = " ".join([v.fn, v.org, " ".join(v.emails)]).lower()
            hit = _matches(q, hay)
            if not hit and len(qdigits) >= 7:
                hit = any(qdigits in "".join(c for c in t if c.isdigit()) for t in v.tels)
            if hit:
                out.append({**_contact_summary(v), "account": cfg.name})
    _audit("search_contacts", f"q={query!r} account={account or 'configured'} n={len(out)}")
    return out[:limit]


@mcp.tool(title="Look up an email address",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def lookup_contact_email(name: str, account: str | None = None) -> dict:
    """Find email addresses for a person by name, before composing a message.

    Returns EVERY match rather than choosing one. Picking the wrong recipient is
    not recoverable, so disambiguating is the caller's job.
    Reads the account set by [contacts].account. account="all" spans them all.
    """
    q = (name or "").strip().lower()
    if not q:
        raise ToolError("name is required")
    matches = [
        {**_contact_summary(v), "account": cfg.name}
        for cfg in _fanout(account, service="contacts")
        for v in _carddav(cfg).fetch_all()
        if not v.is_group and v.emails and _matches(q, f"{v.fn} {v.org}")
    ]
    _audit("lookup_contact_email", f"name={name!r} matches={len(matches)}")
    return {
        "query": name,
        "match_count": len(matches),
        "matches": matches,
        "note": ("Several people match. Confirm which one before sending."
                 if len(matches) > 1 else None),
    }


@mcp.tool(title="List contact groups",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def list_contact_groups(account: str | None = None) -> list[dict]:
    """List Contacts groups and their member counts (read-only).

    Reads the account set by [contacts].account. account="all" spans them all.
    """
    groups = [
        {"name": g.fn.strip(), "members": len(g.members), "uid": g.uid, "account": cfg.name}
        for cfg in _fanout(account, service="contacts")
        for g in _carddav(cfg).fetch_all() if g.is_group
    ]
    groups.sort(key=lambda d: -d["members"])
    return groups


# ===================== ORGANIZE (gated writes) =====================
@mcp.tool(title="Mark as read",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
@_guard
def mark_read(uid: int, folder: str = "INBOX", account: str | None = None) -> dict:
    """Mark a message read (write)."""
    _reader(account).mark_read(uid, folder)
    _audit("mark_read", f"{folder}#{uid}")
    return {"ok": True}


@mcp.tool(title="Flag a message",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
@_guard
def flag(uid: int, folder: str = "INBOX", account: str | None = None) -> dict:
    """Flag a message (write)."""
    _reader(account).flag(uid, folder)
    _audit("flag", f"{folder}#{uid}")
    return {"ok": True}


@mcp.tool(title="Move a message",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
@_guard
def move_message(uid: int, dest_folder: str, folder: str = "INBOX", account: str | None = None) -> dict:
    """Move a message to another folder (write; creates the folder if missing)."""
    _reader(account).move_message(uid, dest_folder, folder)
    _audit("move_message", f"{folder}#{uid} -> {dest_folder}")
    return {"ok": True}


@mcp.tool(title="Move mail to Trash",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False))
@_guard
def trash(uids: list[int], folder: str = "INBOX", account: str | None = None) -> dict:
    """Move messages to Trash. Recoverable until the user empties it.

    Use this for cleanup rather than move_message: it resolves the Trash folder
    by its \\Trash special-use flag, so the caller does not need to know iCloud
    names it "Deleted Messages".
    """
    n, dest = _reader(account).trash(uids, folder)
    _audit("trash", f"{folder} n={n} -> {dest}")
    return {"ok": True, "trashed": n, "folder": dest,
            "note": "Recoverable from Trash until emptied. Not a permanent delete."}


@mcp.tool(title="Archive a message",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
@_guard
def archive(uid: int, folder: str = "INBOX", account: str | None = None) -> dict:
    """Archive a message (move to Archive) (write)."""
    _reader(account).archive(uid, folder)
    _audit("archive", f"{folder}#{uid}")
    return {"ok": True}


@mcp.tool(title="Apply cleanup rules",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False))
@_guard
def apply_rules(dry_run: bool = True, window_days: int | None = None, account: str | None = None) -> dict:
    """Apply cleanup rules to recent mail. DRY-RUN by default: shows the plan and
    changes nothing. Pass dry_run=False to execute. 'delete' actions only run if
    [cleanup].allow_delete is true in config."""
    cfg = _cfg(account)
    msgs = _reader(account).list_inbox(since_days=window_days)
    plan = plan_cleanup(msgs, cfg.cleanup_rules, cfg.allow_delete,
                        protected_senders=set(cfg.protected_senders))
    if dry_run:
        _audit("apply_rules", f"dry_run plan={len(plan)}")
        return {"dry_run": True, "planned": plan, "count": len(plan)}

    reader = _reader(account)
    done = []
    for item in plan:
        act, uid = item["action"], item["uid"]
        try:
            if act == "archive":
                reader.archive(uid)
            elif act == "mark_read":
                reader.mark_read(uid)
            elif act == "move":
                if folder_blocked(item["folder"]):
                    done.append({**item, "result": "refused: blocked folder"})
                    continue
                reader.move_message(uid, item["folder"])
            elif act == "delete":
                # "Delete" means Trash, recoverable. Never expunge from here.
                reader.trash([uid])
            elif act == "skip":
                continue
            done.append({**item, "result": "done"})
        except Exception as e:  # noqa: BLE001
            done.append({**item, "result": f"error: {e}"})
    _audit("apply_rules", f"executed={len(done)}")
    return {"dry_run": False, "executed": done, "count": len(done)}


# ===================== SEND (gated) =====================
@mcp.tool(title="Prepare a reply draft",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def draft_reply(uid: int, instructions: str, folder: str = "INBOX", account: str | None = None) -> dict:
    """Return a draft reply for review. Does NOT send. The caller/model writes the
    actual prose; this returns the original + threading info to reply against."""
    m = _reader(account).get_message(uid, folder=folder)
    if m is None:
        return {"error": "not_found", "detail": f"uid {uid}"}
    return {
        "reply_to": m.from_addr,
        "subject": m.subject if m.subject.lower().startswith("re:") else f"Re: {m.subject}",
        "in_reply_to": m.headers.get("message-id"),
        "references": m.headers.get("references"),
        "original_snippet": (m.body_text or "")[:1000],
        "instructions": instructions,
        "note": "Compose the reply, then call reply_mail (confirm=True for a new recipient).",
    }


@mcp.tool(title="Send an email",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True))
@_guard
def send_mail(to: str, subject: str, body: str, confirm: bool = False,
              cc: list[str] | None = None,
              attachments: list[str] | None = None, account: str | None = None) -> dict:
    """Send a new email. Learn-on-approve: a NEW recipient requires confirm=True.

    `to` may carry several comma-separated addresses. Every one of them, and every
    cc, is gated and trusted individually. Use cc rather than packing a third party
    into `to`: the header is what the recipients actually see.

    attachments: absolute paths to files to attach.
    """
    res = _sender(account).send(to, subject, body, confirm=confirm, cc=cc,
                                attachments=attachments)
    _audit("send_mail", f"to={to} cc={cc or []} sent={res.sent} confirm={confirm} "
                        f"attachments={len(attachments or [])} "
                        f"trusted_new={res.newly_trusted}")
    return res.as_dict()


@mcp.tool(title="Reply to an email",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True))
@_guard
def reply_mail(uid: int, body: str, confirm: bool = False, folder: str = "INBOX",
               reply_all: bool = False, account: str | None = None) -> dict:
    """Reply to a message by uid (threaded). Learn-on-approve gating applies.

    reply_all=True keeps the original To/Cc recipients (minus you) on the thread.
    Threading headers are sent either way.
    """
    m = _reader(account).get_message(uid, folder=folder)
    if m is None:
        raise ToolError(f"no message with uid {uid} in {folder}")
    subject = m.subject if m.subject.lower().startswith("re:") else f"Re: {m.subject}"
    cc = None
    if reply_all:
        cc = reply_recipients(
            sender=m.from_addr,
            to_header=m.headers.get("to", ""),
            cc_header=m.headers.get("cc", ""),
            me=_cfg(account).address,
        )
    res = _sender(account).send(
        m.from_addr, subject, body, confirm=confirm, cc=cc,
        in_reply_to=m.headers.get("message-id"),
        references=m.headers.get("references"),
    )
    _audit("reply_mail", f"to={m.from_addr} cc={cc or []} sent={res.sent} "
                         f"trusted_new={res.newly_trusted}")
    return res.as_dict()


@mcp.tool(title="Reset approved recipients",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False))
@_guard
def reset_trusted_recipients(account: str | None = None) -> dict:
    """Clear the learn-on-approve trusted-recipients store."""
    _sender(account).trusted.clear()
    _audit("reset_trusted_recipients", "cleared")
    return {"ok": True}


# ===================== UNSUBSCRIBE (light) =====================
@mcp.tool(title="Find unsubscribe method",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def find_unsubscribe(uid: int, folder: str = "INBOX", account: str | None = None) -> dict:
    """Parse the unsubscribe options for a message. Does not act."""
    m = _reader(account).get_message(uid, folder=folder)
    if m is None:
        return {"error": "not_found", "detail": f"uid {uid}"}
    plan = parse_unsubscribe(m)
    return {"method": plan.method, "target": plan.target, "reason": plan.reason}


@mcp.tool(title="Unsubscribe from a sender",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True))
@_guard
def do_unsubscribe(uid: int, folder: str = "INBOX", account: str | None = None,
                   confirm: bool = False) -> dict:
    """Execute standardized one-click unsubscribe (RFC 8058 POST) only. For mailto,
    sends the unsubscribe email, which is outbound mail like any other: it needs
    sending enabled and, for an address not yet trusted, confirm=True after the user
    agrees. Webpage-only senders return 'manual' for you to tap."""
    m = _reader(account).get_message(uid, folder=folder)
    if m is None:
        return {"error": "not_found", "detail": f"uid {uid}"}
    plan = parse_unsubscribe(m)
    if plan.method == "one-click":
        ok, detail = execute_one_click(plan.target)
        _audit("do_unsubscribe", f"one-click {m.from_addr} ok={ok}")
        return {"method": "one-click", "ok": ok, "detail": detail}
    if plan.method == "mailto":
        res = _sender(account).send(plan.target, "unsubscribe", "unsubscribe",
                                    confirm=confirm)
        _audit("do_unsubscribe", f"mailto {plan.target} ok={res.sent} "
                                 f"trusted_new={res.newly_trusted}")
        return {"method": "mailto", "ok": res.sent, "detail": res.detail,
                "needs_confirmation": res.needs_confirmation}
    _audit("do_unsubscribe", f"{plan.method} {m.from_addr}")
    return {"method": plan.method, "ok": False, "target": plan.target, "detail": plan.reason}


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    mcp.run()  # stdio transport




# ===================== BULK CLEANUP =====================
# Read-only census and preview; writes need confirm=True and never purge.
# The age guard and protect.py rules are enforced in cleanup.py, not here, so a
# caller cannot skip them by calling a tool in a different order.

@mcp.tool(title="Rank senders by volume",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def sender_census(window_days: int = 730, protect_days: int = 90, limit: int = 25,
                  account: str | None = None) -> dict:
    """Rank INBOX senders by how much mail they sent. READ-ONLY, marks nothing read.

    Each sender splits into: deletable, blocked (a person or a record, see
    protect.py), and protected_by_age (inside the protect_days guard). Sort by
    volume alone and you will surface the people you correspond with most, which
    is the trap this split exists to expose.
    """
    rows = []
    for cfg in _accounts().fanout(account):
        for s in _cleanup.census(cfg, window_days, protect_days)[:limit]:
            rows.append({**s.as_dict(), "account": cfg.name})
    rows.sort(key=lambda r: -r["total"])
    rows = rows[:limit]
    _audit("sender_census", f"window={window_days}d senders={len(rows)}")
    return {
        "window_days": window_days, "protect_days": protect_days,
        "senders": rows,
        "totals": {
            "deletable": sum(r["deletable"] for r in rows),
            "blocked": sum(r["blocked"] for r in rows),
            "inside_guard": sum(r["protected_by_age"] for r in rows),
        },
    }


@mcp.tool(title="Preview a cleanup",
          annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
@_guard
def cleanup_preview(senders: list[str], window_days: int = 730, protect_days: int = 90,
                    account: str | None = None) -> dict:
    """Show exactly what a bulk_trash would take and what it would refuse. CHANGES NOTHING.

    Read the block_samples before approving. A count alone hides whether the
    "marketing" you are about to delete is really booking confirmations.
    """
    out = []
    for cfg in _accounts().fanout(account):
        p = _cleanup.preview(cfg, senders, window_days, protect_days)
        out.append({k: v for k, v in p.items() if k != "_uids"})
    _audit("cleanup_preview", f"senders={len(senders)} accounts={len(out)}")
    return {"accounts": out,
            "would_trash": sum(a["would_trash"] for a in out),
            "would_block": sum(a["would_block"] for a in out)}


@mcp.tool(title="Bulk move mail to Trash",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False))
@_guard
def bulk_trash(senders: list[str], window_days: int = 730, protect_days: int = 90,
               confirm: bool = False, account: str | None = None) -> dict:
    """Move old mail from named senders to Trash. Recoverable; NEVER purges.

    Without confirm=True this returns the preview and moves nothing. Every message
    is re-dated immediately before the move, and the run aborts rather than
    partially deleting if anything drifted inside the guard.
    """
    # fanout, not require_one: account=None means the DEFAULT account, and
    # account="all" is an explicit, deliberate choice. Never silently span every
    # account just because none was named. Unlike create_event, trashing on two
    # accounts is not duplication, and it is recoverable, so "all" is allowed.
    out = []
    for cfg in _accounts().fanout(account):
        out.append(_cleanup.bulk_trash(cfg, senders, window_days, protect_days,
                                       confirm=confirm))
    total = sum(a.get("trashed", 0) for a in out)
    _audit("bulk_trash", f"senders={len(senders)} confirm={confirm} trashed={total}")
    return {"accounts": out, "trashed": total,
            "needs_confirmation": not confirm}


@mcp.tool(title="Recover mail from Trash",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
@_guard
def recover_from_trash(senders: list[str] | None = None, subject_contains: str | None = None,
                       records_only: bool = False, confirm: bool = False,
                       account: str | None = None) -> dict:
    """Move messages back from Trash to INBOX. Without confirm=True, only reports.

    records_only=True selects exactly what protect.py would have shielded, which
    is how you undo a sweep that ran before those rules existed.
    """
    out = []
    for cfg in _accounts().fanout(account):
        out.append(_cleanup.recover(cfg, senders, subject_contains, records_only,
                                    confirm=confirm))
    total = sum(a.get("recovered", 0) for a in out)
    _audit("recover_from_trash", f"records_only={records_only} confirm={confirm} moved={total}")
    return {"accounts": out, "recovered": total, "needs_confirmation": not confirm}


# Must stay the LAST statement in this module. `python -m icloud_mcp.server` runs
# the file top to bottom, so any tool defined below this line would silently be
# missing from the server. The bulk-cleanup tools once were.
if __name__ == "__main__":
    main()
