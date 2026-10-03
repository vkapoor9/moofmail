"""Bulk cleanup safety, tested against a fake IMAP server.

The properties worth testing here are the ones that cost real mail when they are
absent: the age guard, protection of people and records, and the refusal to act
at all when a plan has gone stale.
"""
from __future__ import annotations

import datetime as dt

import pytest

from icloud_mcp import cleanup
from icloud_mcp.config import Config

NOW = dt.datetime.now(dt.timezone.utc)


def env(mbox, host, subject, name=""):
    class A:
        pass
    a = A(); a.mailbox = mbox.encode(); a.host = host.encode(); a.name = name.encode()

    class E:
        pass
    e = E(); e.from_ = [a]; e.subject = subject.encode()
    return e


class FakeIMAP:
    """Minimal stand-in. Records what was copied/expunged so tests can assert."""

    def __init__(self, msgs):
        self.msgs = msgs                 # uid -> (addr, subject, days_old)
        self.selected = None
        self.readonly = None
        self.copied: list[tuple[list[int], str]] = []
        self.expunged: list[int] = []

    def select_folder(self, folder, readonly=False):
        self.selected, self.readonly = folder, readonly

    def search(self, criteria):
        return sorted(self.msgs)

    def fetch(self, uids, keys):
        out = {}
        for u in uids:
            if u not in self.msgs:
                continue
            addr, subj, age = self.msgs[u]
            mbox, host = addr.split("@")
            d = {b"INTERNALDATE": NOW - dt.timedelta(days=age)}
            if any("ENVELOPE" in k for k in keys):
                d[b"ENVELOPE"] = env(mbox, host, subj)
            out[u] = d
        return out

    def copy(self, uids, dest):
        self.copied.append((list(uids), dest))

    def add_flags(self, uids, flags):
        pass

    def expunge(self, uids=None):
        self.expunged.extend(uids or [])

    def move(self, uids, dest):
        from imapclient.exceptions import CapabilityError
        raise CapabilityError("iCloud has no MOVE")

    def list_folders(self):
        return [((rb"\Trash",), b"/", "Deleted Messages"), ((), b"/", "INBOX")]


@pytest.fixture
def cfg():
    return Config(address="me@icloud.com", name="test",
                  protected_senders=["friend@example.com"])


@pytest.fixture
def wire(monkeypatch):
    """Point MailReader at a FakeIMAP and hand the fake back to the test."""
    def _wire(msgs):
        fake = FakeIMAP(msgs)
        monkeypatch.setattr(cleanup.MailReader, "client", lambda self: fake)
        monkeypatch.setattr(cleanup, "find_trash_folder", lambda c: "Deleted Messages")
        return fake
    return _wire


MSGS = {
    1: ("newsletter@shop.example.com", "Meet the New Collection", 400),                       # deletable
    2: ("newsletter@shop.example.com", "New Arrivals This Week", 30),                  # inside guard
    3: ("notifications@airline.example.com", "Your Example Airlines booking confirmation - ABC123", 400),
    4: ("notifications@airline.example.com", "Your Example Lounge one-time passes inside", 400),
    5: ("friend@example.com", "dinner?", 400),                            # protected person
}


def test_census_splits_three_ways(cfg, wire):
    wire(MSGS)
    rows = {s.address: s for s in cleanup.census(cfg, window_days=730, protect_days=90)}
    shop = rows["newsletter@shop.example.com"]
    assert (shop.total, shop.deletable, shop.protected_by_age) == (2, 1, 1)
    airline = rows["notifications@airline.example.com"]
    assert (airline.deletable, airline.blocked) == (1, 1)      # passes yes, booking no
    assert rows["friend@example.com"].blocked == 1


def test_census_uids_carry_only_deletable(cfg, wire):
    wire(MSGS)
    rows = {s.address: s for s in cleanup.census(cfg)}
    assert rows["notifications@airline.example.com"].uids == [4]      # never the booking
    assert rows["friend@example.com"].uids == []


def test_preview_changes_nothing_and_explains_blocks(cfg, wire):
    fake = wire(MSGS)
    p = cleanup.preview(cfg, ["notifications@airline.example.com"])
    assert p["would_trash"] == 1 and p["would_block"] == 1
    assert "protected subject (travel)" in p["senders"][0]["block_samples"][0]["reason"]
    assert fake.copied == [] and fake.expunged == []
    assert fake.readonly is True


def test_bulk_trash_without_confirm_moves_nothing(cfg, wire):
    fake = wire(MSGS)
    r = cleanup.bulk_trash(cfg, ["newsletter@shop.example.com"])
    assert r["needs_confirmation"] is True and r["trashed"] == 0
    assert fake.copied == []


def test_bulk_trash_confirm_moves_only_the_safe_one(cfg, wire):
    fake = wire(MSGS)
    r = cleanup.bulk_trash(cfg, ["notifications@airline.example.com"], confirm=True)
    assert r["trashed"] == 1
    assert fake.copied == [([4], "Deleted Messages")]        # the lounge passes only
    assert 3 not in fake.expunged                            # booking never touched


def test_bulk_trash_never_takes_a_protected_person(cfg, wire):
    fake = wire(MSGS)
    r = cleanup.bulk_trash(cfg, ["friend@example.com"], confirm=True)
    assert r["trashed"] == 0 and fake.copied == []


def test_bulk_trash_aborts_when_a_message_drifts_inside_the_guard(cfg, wire, monkeypatch):
    """A stale plan must abort the WHOLE run, not delete the half that still qualifies."""
    fake = wire(MSGS)
    real_preview = cleanup.preview

    def stale(*a, **k):
        p = real_preview(*a, **k)
        p["_uids"]["newsletter@shop.example.com"] = [1, 2]      # uid 2 is only 30 days old
        return p
    monkeypatch.setattr(cleanup, "preview", stale)

    with pytest.raises(ValueError, match="ABORTED"):
        cleanup.bulk_trash(cfg, ["newsletter@shop.example.com"], confirm=True)
    assert fake.copied == []                             # nothing moved at all


def test_recover_records_only_finds_the_booking(cfg, wire):
    fake = wire(MSGS)
    r = cleanup.recover(cfg, records_only=True, confirm=True)
    assert r["recovered"] == 2                           # the booking and the friend
    assert fake.copied and fake.copied[0][1] == "INBOX"


def test_recover_without_confirm_reports_only(cfg, wire):
    fake = wire(MSGS)
    r = cleanup.recover(cfg, senders=["notifications@airline.example.com"])
    assert r["needs_confirmation"] is True and r["recovered"] == 0
    assert fake.copied == []
