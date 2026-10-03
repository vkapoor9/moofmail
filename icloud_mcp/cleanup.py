"""Bulk inbox cleanup: census, preview, trash, recover.

Every safety property is enforced HERE rather than left to the caller, because
the caller is the thing that forgets. A top-25 sweep by volume can take
thousands of messages and then have to hand hundreds back.

Four rules this module will not let you break:

1. **The age guard is re-checked at delete time.** Candidate lists are built from
   one fetch and acted on in another. A message that drifted inside the guard, or
   a bug in the census, must not become a deletion, so `bulk_trash` re-reads
   INTERNALDATE and refuses the whole run if anything is too new.
2. **Protection is applied to every candidate** (see protect.py): people you
   correspond with, and records like booking confirmations and statements.
3. **Nothing is ever purged.** Everything goes to Trash via COPY-then-expunge.
4. **Writes need `confirm=True`.** The preview is the default path.

Reads use ENVELOPE rather than full-header fetches. On a two-year window that is
the difference between a couple of minutes and a very long wait.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field

from imapclient import IMAPClient

from .config import Config
from .imap_read import MailReader, find_trash_folder
from .models import decode_mime_header
from .protect import deletion_block

DEFAULT_WINDOW_DAYS = 730
DEFAULT_PROTECT_DAYS = 90
_FETCH_BATCH = 400
_ACT_BATCH = 200


@dataclass
class SenderStat:
    address: str
    name: str = ""
    total: int = 0
    protected_by_age: int = 0     # inside the guard, never touched
    deletable: int = 0            # outside the guard AND not otherwise protected
    blocked: int = 0              # outside the guard but protected by sender/subject
    first: str = ""
    last: str = ""
    uids: list[int] = field(default_factory=list)   # deletable only

    def as_dict(self, with_uids: bool = False) -> dict:
        d = {
            "address": self.address, "name": self.name, "total": self.total,
            "protected_by_age": self.protected_by_age, "deletable": self.deletable,
            "blocked": self.blocked, "first": self.first, "last": self.last,
        }
        if with_uids:
            d["uids"] = self.uids
        return d


def _envelope_rows(c: IMAPClient, folder: str, since: dt.date | None):
    """Yield (uid, from_addr, from_name, subject, when) for a folder. Read-only."""
    c.select_folder(folder, readonly=True)
    uids = c.search(["SINCE", since] if since else ["ALL"])
    for i in range(0, len(uids), _FETCH_BATCH):
        resp = c.fetch(uids[i:i + _FETCH_BATCH], ["ENVELOPE", "INTERNALDATE"])
        for uid, data in resp.items():
            env = data.get(b"ENVELOPE")
            if env is None:
                continue
            addr = name = ""
            if env.from_:
                f = env.from_[0]
                mbox = (f.mailbox or b"").decode("utf-8", "replace")
                host = (f.host or b"").decode("utf-8", "replace")
                addr = f"{mbox}@{host}".lower() if mbox and host else ""
                name = (f.name or b"").decode("utf-8", "replace")
            subj = (env.subject or b"").decode("utf-8", "replace")
            try:
                subj = decode_mime_header(subj)
                name = decode_mime_header(name) if name else ""
            except Exception:  # noqa: BLE001 - a bad header must not stop a scan
                pass
            when = data.get(b"INTERNALDATE")
            if when is not None and when.tzinfo is None:
                when = when.replace(tzinfo=dt.timezone.utc)
            yield uid, addr, " ".join(name.split()), " ".join(subj.split()), when


def census(cfg: Config, window_days: int = DEFAULT_WINDOW_DAYS,
           protect_days: int = DEFAULT_PROTECT_DAYS,
           folder: str = "INBOX") -> list[SenderStat]:
    """Rank senders by volume, splitting each into deletable / blocked / too-new.

    Read-only. `uids` on each row carries ONLY the deletable messages, so a
    caller cannot accidentally act on a protected one by passing the list along.
    """
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=protect_days)
    since = dt.date.today() - dt.timedelta(days=window_days)
    protected = set(cfg.protected_senders)
    out: dict[str, SenderStat] = {}

    c = MailReader(cfg).client()
    for uid, addr, name, subj, when in _envelope_rows(c, folder, since):
        if not addr:
            continue
        s = out.setdefault(addr, SenderStat(address=addr))
        s.total += 1
        s.name = s.name or name
        if when is not None:
            iso = when.date().isoformat()
            s.first = min(s.first, iso) if s.first else iso
            s.last = max(s.last, iso) if s.last else iso
        if when is None or when >= cutoff:
            s.protected_by_age += 1          # unknown date is treated as too new
        elif deletion_block(addr, subj, protected):
            s.blocked += 1
        else:
            s.deletable += 1
            s.uids.append(uid)
    return sorted(out.values(), key=lambda s: -s.total)


def preview(cfg: Config, senders: list[str], window_days: int = DEFAULT_WINDOW_DAYS,
            protect_days: int = DEFAULT_PROTECT_DAYS, folder: str = "INBOX",
            samples: int = 4) -> dict:
    """What a bulk_trash of `senders` would take, and what it would refuse. No writes.

    Returns a per-sender breakdown plus sample subjects on both sides, because a
    count alone hides the thing that matters: whether the "marketing" you are
    about to delete is actually booking confirmations.
    """
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=protect_days)
    since = dt.date.today() - dt.timedelta(days=window_days)
    want = {s.strip().lower() for s in senders if s.strip()}
    protected = set(cfg.protected_senders)

    rows: dict[str, dict] = {
        a: {"address": a, "take": 0, "block": 0, "too_new": 0,
            "take_samples": [], "block_samples": [], "uids": []} for a in want
    }
    c = MailReader(cfg).client()
    for uid, addr, _name, subj, when in _envelope_rows(c, folder, since):
        if addr not in want:
            continue
        r = rows[addr]
        if when is None or when >= cutoff:
            r["too_new"] += 1
            continue
        why = deletion_block(addr, subj, protected)
        if why:
            r["block"] += 1
            if len(r["block_samples"]) < samples:
                r["block_samples"].append({"subject": subj, "reason": why})
        else:
            r["take"] += 1
            r["uids"].append(uid)
            if len(r["take_samples"]) < samples:
                r["take_samples"].append(subj)

    ordered = sorted(rows.values(), key=lambda r: -r["take"])
    return {
        "account": cfg.name,
        "window_days": window_days,
        "protect_days": protect_days,
        "guard_cutoff": cutoff.date().isoformat(),
        "would_trash": sum(r["take"] for r in ordered),
        "would_block": sum(r["block"] for r in ordered),
        "inside_guard": sum(r["too_new"] for r in ordered),
        "senders": [{k: v for k, v in r.items() if k != "uids"} for r in ordered],
        "_uids": {r["address"]: r["uids"] for r in ordered},
    }


def bulk_trash(cfg: Config, senders: list[str], window_days: int = DEFAULT_WINDOW_DAYS,
               protect_days: int = DEFAULT_PROTECT_DAYS, folder: str = "INBOX",
               confirm: bool = False) -> dict:
    """Move old mail from `senders` to Trash. Recoverable, never purged.

    Without confirm=True this returns the preview and changes nothing.

    The plan is rebuilt from scratch here rather than trusting a uid list handed
    in by a caller, and every uid is re-dated immediately before the move. If
    anything has drifted inside the guard the whole run aborts, because a partial
    bulk delete is worse than none: you cannot tell which half ran.
    """
    plan = preview(cfg, senders, window_days, protect_days, folder)
    if not confirm:
        plan["trashed"] = 0
        plan["needs_confirmation"] = True
        plan["note"] = "Nothing moved. Re-run with confirm=True to execute this plan."
        return plan

    uids = [u for lst in plan["_uids"].values() for u in lst]
    if not uids:
        return {**{k: v for k, v in plan.items() if k != "_uids"},
                "trashed": 0, "needs_confirmation": False, "note": "nothing to move"}

    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=protect_days)
    r = MailReader(cfg)
    c = r.client()
    c.select_folder(folder, readonly=True)
    too_new = []
    for i in range(0, len(uids), _FETCH_BATCH):
        for uid, data in c.fetch(uids[i:i + _FETCH_BATCH], ["INTERNALDATE"]).items():
            when = data.get(b"INTERNALDATE")
            if when is None:
                too_new.append(uid)
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=dt.timezone.utc)
            if when >= cutoff:
                too_new.append(uid)
    if too_new:
        raise ValueError(
            f"ABORTED before moving anything: {len(too_new)} of {len(uids)} messages "
            f"are inside the {protect_days}-day guard. Re-run the census; the plan is stale."
        )

    moved, dest = 0, ""
    for i in range(0, len(uids), _ACT_BATCH):
        n, dest = r.trash(uids[i:i + _ACT_BATCH], folder=folder)
        moved += n
    return {**{k: v for k, v in plan.items() if k != "_uids"},
            "trashed": moved, "destination": dest, "needs_confirmation": False,
            "verified_outside_guard": len(uids)}


def recover(cfg: Config, senders: list[str] | None = None,
            subject_contains: str | None = None, records_only: bool = False,
            to_folder: str = "INBOX", confirm: bool = False) -> dict:
    """Move messages back out of Trash. Without confirm=True, only reports.

    `records_only=True` selects exactly what protect.py would have shielded, which
    is the fast way to undo a sweep that ran before those rules existed.
    """
    want = {s.strip().lower() for s in (senders or []) if s.strip()}
    needle = (subject_contains or "").strip().lower()
    protected = set(cfg.protected_senders)

    r = MailReader(cfg)
    c = r.client()
    trash = find_trash_folder(c)
    hits, samples = [], []
    for uid, addr, _n, subj, _w in _envelope_rows(c, trash, None):
        if want and addr not in want:
            continue
        if needle and needle not in subj.lower():
            continue
        if records_only and not deletion_block(addr, subj, protected):
            continue
        hits.append(uid)
        if len(samples) < 10:
            samples.append({"from": addr, "subject": subj})

    res = {"account": cfg.name, "source": trash, "matched": len(hits),
           "samples": samples, "recovered": 0}
    if not confirm:
        res["needs_confirmation"] = True
        res["note"] = "Nothing moved. Re-run with confirm=True."
        return res
    if hits:
        c.select_folder(trash, readonly=False)
        for i in range(0, len(hits), _ACT_BATCH):
            r._move_uids(c, hits[i:i + _ACT_BATCH], to_folder)
    res["recovered"] = len(hits)
    res["destination"] = to_folder
    res["needs_confirmation"] = False
    return res
