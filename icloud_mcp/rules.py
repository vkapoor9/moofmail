"""Rule matching for triage (VIP) and cleanup.

Pure logic, no I/O, fully unit-testable. Matching is a case-insensitive glob on
the sender address (fnmatch), plus a subject-substring convenience: a match token
with no '@' and no glob chars is treated as a plain substring test against subject.
"""
from __future__ import annotations

import fnmatch

from .config import TriageRule, CleanupRule
from .models import Message
from .protect import deletion_block

_PRIORITY_ORDER = {"high": 3, "normal": 2, "low": 1}


def _matches(token: str, msg: Message) -> bool:
    """Does `token` match this message?

    - If the token looks like an address glob (contains '@' or glob chars),
      match it against the From address with fnmatch.
    - Otherwise treat it as a case-insensitive substring against the subject
      (covers rules like "*newsletter*" and plain "receipt").
    """
    t = token.lower().strip()
    addr = msg.from_addr.lower()
    subject = (msg.subject or "").lower()
    is_glob = any(c in t for c in "*?[")
    if "@" in t or (is_glob and "." in t):
        if fnmatch.fnmatch(addr, t):
            return True
    # subject fallback (strip glob stars for substring feel)
    needle = t.strip("*")
    if needle and needle in subject:
        return True
    # also allow pure address globs to still try subject-less address match
    if is_glob and fnmatch.fnmatch(addr, t):
        return True
    return False


def priority_for(msg: Message, rules: list[TriageRule]) -> str | None:
    """Return the highest-priority triage label whose rule matches, else None."""
    best: str | None = None
    best_rank = 0
    for r in rules:
        if _matches(r.match, msg):
            rank = _PRIORITY_ORDER.get(r.priority, 2)
            if rank > best_rank:
                best_rank = rank
                best = r.priority
    return best


def cleanup_action_for(msg: Message, rules: list[CleanupRule]) -> CleanupRule | None:
    """Return the first cleanup rule that matches this message, else None."""
    for r in rules:
        if _matches(r.match, msg):
            return r
    return None


_TRASHY = ("trash", "deleted messages", "deleted items", "junk", "spam")


def plan_cleanup(messages: list[Message], cleanup_rules: list[CleanupRule],
                 allow_delete: bool, protected_senders: set[str] | None = None) -> list[dict]:
    """Pure planning step for apply_rules. Returns one entry per matched message.

    'delete' actions are downgraded to 'skip (delete disabled)' unless allow_delete.
    No side effects, so the tool can always show a dry-run preview first.

    **Destructive actions are additionally blocked for protected mail** (see
    protect.py): correspondence with real people, and records like booking
    confirmations, statements and safety recalls. This is enforced here rather
    than left to the caller because the caller is the thing that forgets. A
    top-25-by-volume sweep would otherwise delete threads with people the user
    corresponds with often, along with booking confirmations.

    Non-destructive actions (mark_read, archive) are never blocked; protection is
    about not losing the message, not about never touching it.
    """
    plan: list[dict] = []
    for m in messages:
        r = cleanup_action_for(m, cleanup_rules)
        if r is None:
            continue
        action = r.action
        effective = action
        note = ""
        destructive = action == "delete" or (
            action == "move" and (r.folder or "").strip().lower() in _TRASHY
        )
        block = (
            deletion_block(m.from_addr, m.subject, protected_senders)
            if destructive else None
        )
        if block:
            effective = "skip"
            note = f"blocked: {block}"
        elif action == "delete" and not allow_delete:
            effective = "skip"
            note = "delete disabled in config ([cleanup].allow_delete = false)"
        plan.append({
            "uid": m.uid,
            "from": m.from_addr,
            "subject": m.subject,
            "action": effective,
            "folder": r.folder,
            "matched": r.match,
            "note": note,
        })
    return plan
