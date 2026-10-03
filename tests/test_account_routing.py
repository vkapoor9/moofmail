"""Which account do contacts and calendar tools actually talk to?

The bug these guard: [calendar].account was parsed into Config and then read by
nobody except a standalone script, so every calendar MCP tool silently queried the
DEFAULT mail account. On a Mac where the calendars and the address book live on
a second account, `agenda` returned an empty day and `search_contacts` returned
"no such person". Both are indistinguishable from a correct empty answer.

No network: the CardDAV/CalDAV clients are replaced with fakes that record which
account they were built for.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from icloud_mcp.caldav import Calendar, Event
from icloud_mcp.carddav import VCard
from icloud_mcp.config import ConfigError, parse_accounts

TWO_ACCOUNTS = {
    "accounts": {
        "main": {"address": "me@me.com", "default": True},
        "work": {"address": "other@icloud.com", "keychain_service": "icloud-mcp-work"},
    },
}


def _data(**sections) -> dict:
    out = {k: dict(v) for k, v in TWO_ACCOUNTS.items()}
    out.update(sections)
    return out


# ------------------------------------------------------- config resolution
def test_contacts_account_is_parsed_from_config():
    accts = parse_accounts(_data(contacts={"account": "work"}))
    assert accts.get("main").contacts_account == "work"


def test_calendar_tools_default_to_the_configured_calendar_account():
    """The actual bug: [calendar].account = work, tools still used main."""
    accts = parse_accounts(_data(calendar={"account": "work"}))
    assert accts.default_name == "main"
    assert accts.get(service="calendar").name == "work"


def test_contacts_tools_default_to_the_configured_contacts_account():
    accts = parse_accounts(_data(contacts={"account": "work"}))
    assert accts.get(service="contacts").name == "work"


def test_an_explicit_account_overrides_the_service_default():
    accts = parse_accounts(_data(calendar={"account": "work"}))
    assert accts.get("main", service="calendar").name == "main"


def test_service_falls_back_to_the_default_account_when_unconfigured():
    accts = parse_accounts(_data())
    assert accts.get(service="calendar").name == "main"
    assert accts.get(service="contacts").name == "main"


def test_an_unknown_service_account_names_the_config_key_that_is_wrong():
    accts = parse_accounts(_data(calendar={"account": "typo"}))
    with pytest.raises(ConfigError) as e:
        accts.get(service="calendar")
    assert "[calendar].account" in str(e.value)
    assert "typo" in str(e.value)


def test_mail_is_unaffected_by_the_calendar_account():
    """Regression guard: routing calendar elsewhere must not move mail."""
    accts = parse_accounts(_data(calendar={"account": "work"}))
    assert accts.get().name == "main"


# ------------------------------------------------------------ fan-out
def test_fanout_all_spans_every_account():
    accts = parse_accounts(_data(calendar={"account": "work"}))
    assert [c.name for c in accts.fanout("all", service="calendar")] == ["main", "work"]


def test_fanout_without_all_uses_the_service_default_only():
    accts = parse_accounts(_data(calendar={"account": "work"}))
    assert [c.name for c in accts.fanout(None, service="calendar")] == ["work"]


# ------------------------------------------------- the tools themselves
class FakeCardDav:
    def __init__(self, cards):
        self._cards = cards

    def fetch_all(self):
        return self._cards


class FakeCalDav:
    def __init__(self, events, calendars=()):
        self._events = events
        self._calendars = list(calendars)

    def events(self, start, end, include=None):
        return self._events

    def calendars(self):
        return self._calendars


# Synthetic throughout. These mirror the SHAPES that matter (a two-word name, and
# further down a name carrying a middle initial) with invented values.
CONTACT = VCard(uid="U1", fn="Marta Kowalczyk", org="Acme Corp",
                emails=["marta@acme.example.com"], tels=["+1 212-555-0100"])


@pytest.fixture
def wired(monkeypatch):
    """Install two accounts and per-account DAV fakes into the server's state."""
    from icloud_mcp import server

    def _install(data, carddav=None, caldav=None):
        accts = parse_accounts(data)
        monkeypatch.setitem(server._state, "accounts", accts)
        monkeypatch.setitem(server._state, "carddav", dict(carddav or {}))
        monkeypatch.setitem(server._state, "caldav", dict(caldav or {}))
        return server

    return _install


def test_search_contacts_looks_in_the_configured_contacts_account(wired):
    """main has an empty address book; the real one is on work."""
    server = wired(
        _data(contacts={"account": "work"}),
        carddav={"main": FakeCardDav([]), "work": FakeCardDav([CONTACT])},
    )
    hits = server.search_contacts("Marta")
    assert [h["name"] for h in hits] == ["Marta Kowalczyk"]


def test_search_contacts_all_spans_accounts_and_tags_each_hit(wired):
    here = VCard(uid="U3", fn="Sam Rivera", org="Rivera Design", emails=["sam@rivera.test"])
    there = VCard(uid="U4", fn="Dana Rivera", org="Rivera Legal", emails=["dana@rivera.test"])
    server = wired(
        _data(contacts={"account": "work"}),
        carddav={"main": FakeCardDav([here]), "work": FakeCardDav([there])},
    )
    hits = server.search_contacts("rivera", account="all")
    assert {h["account"] for h in hits} == {"main", "work"}


def test_lookup_contact_email_looks_in_the_contacts_account(wired):
    server = wired(
        _data(contacts={"account": "work"}),
        carddav={"main": FakeCardDav([]), "work": FakeCardDav([CONTACT])},
    )
    assert server.lookup_contact_email("Marta")["match_count"] == 1


def test_list_contact_groups_looks_in_the_contacts_account(wired):
    group = VCard(uid="G1", fn="Business", is_group=True, members=["a", "b"])
    server = wired(
        _data(contacts={"account": "work"}),
        carddav={"main": FakeCardDav([]), "work": FakeCardDav([group])},
    )
    assert [g["name"] for g in server.list_contact_groups()] == ["Business"]


def test_agenda_reads_the_calendar_account(wired):
    ev = Event(uid="E1", summary="Book club", calendar="General",
               start=datetime(2026, 8, 3, 16, 0, tzinfo=timezone.utc),
               end=datetime(2026, 8, 3, 17, 0, tzinfo=timezone.utc))
    server = wired(
        _data(calendar={"account": "work"}),
        caldav={"main": FakeCalDav([]), "work": FakeCalDav([ev])},
    )
    out = server.agenda("today")
    assert out["count"] == 1
    assert "Book club" in out["text"]


def test_list_calendars_reads_the_calendar_account(wired):
    server = wired(
        _data(calendar={"account": "work"}),
        caldav={"main": FakeCalDav([], []),
                "work": FakeCalDav([], [Calendar(name="General", href="/g/")])},
    )
    assert [c["name"] for c in server.list_calendars()] == ["General"]


def test_agenda_all_merges_accounts(wired):
    a = Event(uid="E1", summary="Book club", calendar="General",
              start=datetime(2026, 8, 3, 16, 0, tzinfo=timezone.utc),
              end=datetime(2026, 8, 3, 17, 0, tzinfo=timezone.utc))
    b = Event(uid="E2", summary="Dentist", calendar="Personal",
              start=datetime(2026, 8, 3, 18, 0, tzinfo=timezone.utc),
              end=datetime(2026, 8, 3, 19, 0, tzinfo=timezone.utc))
    server = wired(
        _data(calendar={"account": "work"}),
        caldav={"main": FakeCalDav([b]), "work": FakeCalDav([a])},
    )
    out = server.agenda("today", account="all")
    assert out["count"] == 2
    assert {e["account"] for e in out["events"]} == {"main", "work"}


MIDDLE_INITIAL = VCard(uid="U9", fn="Alan R. Whitfield", org="Globex Ltd",
                       emails=["awhitfield@globex.example.com"])


def test_lookup_finds_a_name_carrying_a_middle_initial(wired):
    """A two-word query used to match nobody when the card carried a middle
    initial. Same silent no-such-person failure as the
    account bug, different cause."""
    server = wired(_data(contacts={"account": "work"}),
                   carddav={"main": FakeCardDav([]), "work": FakeCardDav([MIDDLE_INITIAL])})
    assert server.lookup_contact_email("Alan Whitfield")["match_count"] == 1


def test_lookup_still_refuses_a_different_person_sharing_one_name(wired):
    """Token matching must not turn every shared first name into a match."""
    server = wired(_data(contacts={"account": "work"}),
                   carddav={"main": FakeCardDav([]), "work": FakeCardDav([MIDDLE_INITIAL])})
    assert server.lookup_contact_email("Alan Sorensen")["match_count"] == 0


def test_search_contacts_matches_tokens_out_of_order(wired):
    server = wired(_data(contacts={"account": "work"}),
                   carddav={"main": FakeCardDav([]), "work": FakeCardDav([MIDDLE_INITIAL])})
    assert len(server.search_contacts("whitfield alan")) == 1


def test_search_contacts_still_matches_a_literal_email(wired):
    """Regression guard: tokenising must not break exact-string lookups."""
    server = wired(_data(contacts={"account": "work"}),
                   carddav={"main": FakeCardDav([]), "work": FakeCardDav([MIDDLE_INITIAL])})
    assert len(server.search_contacts("awhitfield@globex.example.com")) == 1


def _at(hour, day_offset=0):
    from datetime import timedelta
    # No [calendar].timezone is configured here, so the server resolves to the
    # machine's local zone. Build the fixtures in the same zone.
    from icloud_mcp.config import system_timezone
    tz = system_timezone()
    base = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    return base + timedelta(days=day_offset, hours=hour)


def test_week_agenda_labels_which_day_each_event_falls_on(wired):
    """A week of bare clock times reads as unsorted: 4:45 PM then 1:00 PM."""
    late_today = Event(uid="E1", summary="Movie", start=_at(16), end=_at(18))
    early_friday = Event(uid="E2", summary="Standup", start=_at(9, 3), end=_at(10, 3))
    server = wired(_data(calendar={"account": "work"}),
                   caldav={"main": FakeCalDav([]),
                           "work": FakeCalDav([late_today, early_friday])})
    text = server.agenda("week")["text"]
    assert _at(9, 3).strftime("%-m/%-d") in text
    # A single day needs no date prefix; it would be noise on every line.
    assert _at(16).strftime("%-m/%-d") not in server.agenda("today")["text"]


def test_agenda_names_an_untitled_event_instead_of_printing_a_blank_line(wired):
    blank = Event(uid="E3", summary="", all_day=True, start=_at(0).date())
    server = wired(_data(calendar={"account": "work"}),
                   caldav={"main": FakeCalDav([]), "work": FakeCalDav([blank])})
    assert server.agenda("today")["text"].strip() == "all day    (untitled)"


def test_status_reports_which_account_serves_each_service(monkeypatch, wired):
    """Discoverability: the routing that caused the bug must be inspectable."""
    from icloud_mcp import server
    monkeypatch.setattr(server, "has_password", lambda *a, **k: True)
    wired(_data(calendar={"account": "work"}, contacts={"account": "work"}))
    out = server.status()
    assert out["serves"] == {"mail": "main", "calendar": "work", "contacts": "work"}


CALENDAR_TOOLS = ["list_calendars", "list_events", "agenda", "free_slots",
                  "create_event", "update_event", "delete_event"]
CONTACTS_TOOLS = ["search_contacts", "lookup_contact_email", "list_contact_groups"]


def test_every_calendar_and_contacts_tool_declares_its_service():
    """Structural guard on the routing bug, not on its symptom.

    A tool that resolves through the bare default-account helper reads the wrong
    mailbox, and no behavioural test notices until someone's contact goes
    missing in production. Assert the guard itself, so a future refactor that
    drops `service=` fails here instead of six weeks later.
    """
    import inspect
    from icloud_mcp import server

    missing = []
    for name, service in ([(n, "calendar") for n in CALENDAR_TOOLS]
                          + [(n, "contacts") for n in CONTACTS_TOOLS]):
        src = inspect.getsource(inspect.unwrap(getattr(server, name)))
        if f'service="{service}"' not in src:
            missing.append(f"{name} (expected service={service!r})")
    assert missing == [], "these resolve their account without a service:\n" + "\n".join(missing)


def test_a_write_tool_refuses_account_all(wired):
    """Fanning out a write is meaningless: it would create the event twice."""
    from mcp.server.fastmcp.exceptions import ToolError
    server = wired(
        _data(calendar={"account": "work"}),
        caldav={"main": FakeCalDav([]), "work": FakeCalDav([])},
    )
    with pytest.raises(ToolError) as e:
        server.create_event("x", "2026-08-03T10:00", "2026-08-03T11:00",
                            confirm=True, account="all")
    # Must be a deliberate refusal naming the choices, not the generic
    # "unknown account 'all'" that happens to contain the word.
    msg = str(e.value)
    assert "unknown account" not in msg.lower()
    assert "main" in msg and "work" in msg
