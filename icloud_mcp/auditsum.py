"""Summarize the audit log for the morning brief.

The audit log records every tool call, but a log nobody reads detects nothing.
This turns the last 24 hours into one line, and flags the handful of events
that should never happen without the owner knowing: trust granted to a new
recipient, a refused remote request, a refused Notes read, the trusted store
being reset.

Honesty rule: a missing or unreadable log is reported as exactly that, never
as a quiet day. An absent log and an idle server look identical otherwise.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

AUDIT_PATH = os.path.expanduser("~/.local/state/icloud-mcp/audit.log")

_SEND_ACTIONS = ("send_mail", "reply_mail")
_TRUSTED_RE = re.compile(r"trusted_new=(\[[^\]]*\])")
_TRASH_N_RE = re.compile(r"(?:^|\s)n=(\d+)")


@dataclass
class AuditSummary:
    ok: bool = True
    error: str = ""
    hours: int = 24
    sends: int = 0
    new_recipients: list[str] = field(default_factory=list)
    remote_calls: int = 0
    remote_identities: list[str] = field(default_factory=list)
    # Identities in the window that NEVER appear earlier in the log. One owner
    # can legitimately appear under more than one identity, so "more than one"
    # is noise; "one we have never seen" is the signal.
    first_seen_identities: list[str] = field(default_factory=list)
    remote_denied: int = 0
    blocked_folders: int = 0
    deletions: int = 0
    trust_resets: int = 0
    malformed: int = 0
    remote_writes: dict = field(default_factory=dict)
    remote_caps_hit: int = 0

    @property
    def alerts(self) -> list[str]:
        """Events worth reading even on a busy morning. Plain ASCII."""
        out = []
        if self.new_recipients:
            out.append(f"new recipient trusted: {', '.join(self.new_recipients)}")
        if self.remote_denied:
            out.append(f"{self.remote_denied} remote request(s) refused")
        if self.first_seen_identities:
            out.append("first-ever remote login by: "
                       f"{', '.join(self.first_seen_identities)}")
        if self.blocked_folders:
            out.append(f"{self.blocked_folders} attempt(s) to read Notes refused")
        if self.trust_resets:
            out.append("trusted recipient list was reset")
        if self.remote_caps_hit:
            out.append(f"{self.remote_caps_hit} phone action(s) stopped by a daily cap")
        if self.remote_writes.get("send", 0) + self.remote_writes.get("reply", 0):
            n = self.remote_writes.get("send", 0) + self.remote_writes.get("reply", 0)
            out.append(f"{n} email(s) sent from the phone")
        return out


def _parse_list(detail: str) -> list[str]:
    m = _TRUSTED_RE.search(detail)
    if not m:
        return []
    try:
        val = ast.literal_eval(m.group(1))
    except (ValueError, SyntaxError):
        return []
    return [str(v) for v in val] if isinstance(val, list) else []


def _sent(detail: str) -> bool:
    return "sent=True" in detail or " ok=True" in detail


def _identity(detail: str) -> str:
    """"<email> <path>" -> the email, trimmed and case-folded. Email is
    case-insensitive, and ME@ vs me@ must not read as a stranger."""
    return detail.rsplit(" ", 1)[0].strip().lower() or "(no email)"


def _deleted(action: str, detail: str) -> bool:
    """One explicit rule per action. Previews and dry runs are not deletions."""
    if action == "delete_event":
        return " ok=True" in detail
    if action == "trash":
        m = _TRASH_N_RE.search(detail)
        return bool(m and int(m.group(1)) > 0)
    if action == "bulk_trash":
        return "confirm=True" in detail
    return False


def summarize(path: str = AUDIT_PATH, now: datetime | None = None,
              hours: int = 24) -> AuditSummary:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    s = AuditSummary(hours=hours)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        return AuditSummary(ok=False, error=f"{type(e).__name__}: {e.strerror or e}",
                            hours=hours)

    identities: dict[str, None] = {}
    seen_before: set[str] = set()
    new: dict[str, None] = {}
    for raw in lines:
        parts = raw.rstrip("\n").split("\t", 2)
        if len(parts) < 2:
            s.malformed += 1
            continue
        ts, action = parts[0], parts[1]
        detail = parts[2] if len(parts) > 2 else ""
        try:
            when = datetime.fromisoformat(ts)
        except ValueError:
            s.malformed += 1
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when < since:
            if action == "remote_request":
                seen_before.add(_identity(detail))
            continue
        if when > now:
            continue

        if action in _SEND_ACTIONS:
            if _sent(detail):
                s.sends += 1
            for a in _parse_list(detail):
                new[a] = None
        elif action == "do_unsubscribe" and detail.startswith("mailto"):
            if _sent(detail):
                s.sends += 1
            for a in _parse_list(detail):
                new[a] = None
        elif action == "remote_request":
            s.remote_calls += 1
            identities[_identity(detail)] = None
        elif action == "remote_write":
            kind = detail.split(" ", 1)[0].removeprefix("kind=")
            if kind in ("send", "reply") and "sent=True" not in detail:
                continue
            s.remote_writes[kind] = s.remote_writes.get(kind, 0) + 1
        elif action == "remote_cap":
            s.remote_caps_hit += 1
        elif action == "remote_denied":
            s.remote_denied += 1
        elif action == "blocked_folder":
            s.blocked_folders += 1
        elif action == "reset_trusted_recipients":
            s.trust_resets += 1
        elif _deleted(action, detail):
            s.deletions += 1

    s.new_recipients = list(new)
    s.remote_identities = list(identities)
    s.first_seen_identities = [i for i in identities if i not in seen_before]
    return s


def format_line(s: AuditSummary) -> str:
    """One ASCII line for the plain-text brief."""
    if not s.ok:
        return f"Audit log: could NOT be read ({s.error}). Activity unknown."
    parts = [
        f"{s.sends} send{'s' if s.sends != 1 else ''}"
        f" ({len(s.new_recipients)} to new recipients)",
        f"{s.remote_calls} remote call{'s' if s.remote_calls != 1 else ''}",
    ]
    if s.remote_writes:
        parts.append("phone writes: " + ", ".join(f"{k} {v}" for k, v in sorted(s.remote_writes.items())))
    if s.deletions:
        parts.append(f"{s.deletions} deletion{'s' if s.deletions != 1 else ''}")
    head = f"Last {s.hours}h: " + " | ".join(parts)
    alerts = s.alerts
    if not alerts:
        return head + " | nothing refused"
    return head + "\nCHECK: " + "; ".join(alerts)
