"""iCalendar parsing, timezone handling and VEVENT building. No network.

Fixtures mirror the three DTSTART shapes actually returned by iCloud.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from icloud_mcp.caldav import (holds_events,
    update_vevent_lines,
    Event, build_vevent, parse_dt, parse_vevent, _escape_text, _unescape_text, _fold,
)

ALLDAY = "BEGIN:VEVENT\r\nUID:A1\r\nSUMMARY:Pay Day\r\nDTSTART;VALUE=DATE:20260807\r\nEND:VEVENT"
UTC_EV = ("BEGIN:VEVENT\r\nUID:B2\r\nSUMMARY:Team lunch\r\nLOCATION:Conference Room B\r\n"
          "DTSTART:20260807T212000Z\r\nDTEND:20260807T225000Z\r\nEND:VEVENT")
TZ_EV = ("BEGIN:VEVENT\r\nUID:C3\r\nSUMMARY:Team lunch\r\n"
         "DTSTART;TZID=America/New_York:20260807T172000\r\n"
         "DTEND;TZID=America/New_York:20260807T185000\r\nEND:VEVENT")


def test_parse_all_day():
    ev = parse_vevent(ALLDAY)
    assert ev.all_day is True
    assert ev.start == date(2026, 8, 7)
    assert isinstance(ev.start, date) and not isinstance(ev.start, datetime)


def test_parse_utc():
    ev = parse_vevent(UTC_EV)
    assert ev.all_day is False
    assert ev.start == datetime(2026, 8, 7, 21, 20, tzinfo=timezone.utc)
    assert ev.location == "Conference Room B"


def test_parse_tzid_keeps_local_time_not_utc():
    """The bug this guards: showing 17:20 as if it were UTC."""
    ev = parse_vevent(TZ_EV)
    assert ev.start.hour == 17 and ev.start.minute == 20
    assert ev.start.tzinfo is not None
    assert ev.start.astimezone(timezone.utc).hour == 21    # 17:20 EDT == 21:20 UTC


def test_parse_unknown_tzid_does_not_crash():
    ev = parse_vevent(TZ_EV.replace("America/New_York", "Mars/Olympus"))
    assert ev.start.hour == 17          # kept floating rather than raising


def test_parse_folded_summary():
    folded = ("BEGIN:VEVENT\r\nUID:D4\r\nSUMMARY:A very long event title that got\r\n"
              "  folded across lines\r\nDTSTART;VALUE=DATE:20260807\r\nEND:VEVENT")
    assert parse_vevent(folded).summary == "A very long event title that got folded across lines"


def test_parse_requires_uid():
    assert parse_vevent("BEGIN:VEVENT\r\nSUMMARY:x\r\nEND:VEVENT") is None


@pytest.mark.parametrize("raw,expected", [
    (r"Lunch\, then gym", "Lunch, then gym"),
    (r"Line one\nLine two", "Line one\nLine two"),
    (r"a\;b", "a;b"),
    (r"back\\slash", "back\\slash"),
])
def test_text_unescaping(raw, expected):
    assert _unescape_text(raw) == expected


def test_escape_roundtrip():
    original = 'Meet Bob, Sue; say "hi"\nsecond line \\ done'
    assert _unescape_text(_escape_text(original)) == original


def test_build_all_day_uses_value_date():
    ics = build_vevent("Pay Day", date(2026, 8, 7), date(2026, 8, 8), all_day=True,
                       now=datetime(2026, 8, 1, tzinfo=timezone.utc))
    assert "DTSTART;VALUE=DATE:20260807" in ics
    assert "DTEND;VALUE=DATE:20260808" in ics
    assert "DTSTAMP:20260801T000000Z" in ics


def test_build_tzid_preserved():
    tz = ZoneInfo("America/New_York")
    ics = build_vevent("Call", datetime(2026, 8, 5, 16, 30, tzinfo=tz),
                       datetime(2026, 8, 5, 17, 0, tzinfo=tz))
    assert "DTSTART;TZID=America/New_York:20260805T163000" in ics
    assert "DTEND;TZID=America/New_York:20260805T170000" in ics


def test_build_escapes_injection_in_summary():
    """A summary must not be able to introduce a real second property.

    Substring counting is the wrong check: "SUMMARY:" may legitimately appear
    inside an escaped value. What matters is that no unfolded LINE begins with a
    second SUMMARY, and that the text survives a round trip intact.
    """
    evil = "Evil\r\nSUMMARY:Injected"
    ics = build_vevent(evil, date(2026, 8, 7), date(2026, 8, 8), all_day=True)
    from icloud_mcp.dav import unfold_lines
    starts = [l for l in unfold_lines(ics) if l.upper().startswith("SUMMARY:")]
    assert len(starts) == 1                       # only one real property
    assert parse_vevent(ics).summary == evil.replace("\r\n", "\n")


def test_build_roundtrips_through_the_parser():
    tz = ZoneInfo("America/New_York")
    ics = build_vevent("Lunch, with Bob", datetime(2026, 8, 5, 12, 0, tzinfo=tz),
                       datetime(2026, 8, 5, 13, 0, tzinfo=tz), location="Cafe; downtown")
    ev = parse_vevent(ics)
    assert ev.summary == "Lunch, with Bob"
    assert ev.location == "Cafe; downtown"
    assert ev.start.hour == 12


def test_build_attendees_emit_mailto():
    ics = build_vevent("Sync", date(2026, 8, 7), date(2026, 8, 8), all_day=True,
                       attendees=["a@x.com", "b@y.com"], organizer="me@me.com")
    assert ics.count("ATTENDEE") == 2
    assert "ORGANIZER:mailto:me@me.com" in ics


def test_fold_respects_75_octets():
    long_line = "SUMMARY:" + ("x" * 200)
    folded = _fold(long_line)
    for seg in folded.split("\r\n"):
        assert len(seg.encode()) <= 75
    assert "\r\n " in folded


RECURRING = ("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:R1\r\nSUMMARY:Book club\r\n"
             "DTSTART;TZID=America/New_York:20260807T160000\r\n"
             "RRULE:FREQ=WEEKLY;BYDAY=FR\r\n"
             "BEGIN:VALARM\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n"
             "END:VEVENT\r\nEND:VCALENDAR")


def test_update_preserves_rrule_and_alarms():
    """The whole reason updates edit in place instead of regenerating."""
    out = update_vevent_lines(RECURRING, {"SUMMARY": ("", "Reading group")})
    assert "RRULE:FREQ=WEEKLY;BYDAY=FR" in out
    assert "BEGIN:VALARM" in out and "TRIGGER:-PT15M" in out
    assert "SUMMARY:Reading group" in out
    assert "Book club" not in out


def test_update_replaces_params_not_just_value():
    out = update_vevent_lines(RECURRING,
                              {"DTSTART": (";TZID=Europe/London", "20260807T180000")})
    assert "DTSTART;TZID=Europe/London:20260807T180000" in out
    assert "America/New_York" not in out


def test_update_appends_a_missing_property_before_end():
    out = update_vevent_lines(RECURRING, {"LOCATION": ("", "Studio B")})
    lines = [l for l in out.replace("\r\n", "\n").split("\n") if l]
    assert "LOCATION:Studio B" in lines
    assert lines.index("LOCATION:Studio B") < lines.index("END:VEVENT")


def test_update_matches_a_folded_property():
    folded = ("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:F1\r\n"
              "SUMMARY:A title that was\r\n  folded across lines\r\n"
              "END:VEVENT\r\nEND:VCALENDAR")
    out = update_vevent_lines(folded, {"SUMMARY": ("", "Short")})
    assert "SUMMARY:Short" in out
    assert "folded across lines" not in out


def test_update_with_no_changes_is_a_noop():
    assert update_vevent_lines(RECURRING, {}) == RECURRING


def test_event_to_dict_is_json_safe():
    d = parse_vevent(TZ_EV).to_dict()
    assert d["start"].startswith("2026-08-07T17:20")
    assert d["all_day"] is False


TZ_WITH_VTIMEZONE = (
    "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:T1\r\nSUMMARY:Dentist\r\n"
    "DTSTART;TZID=America/New_York:20260812T100000\r\nEND:VEVENT\r\n"
    "BEGIN:VTIMEZONE\r\nTZID:America/New_York\r\nBEGIN:DAYLIGHT\r\n"
    "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU\r\nEND:DAYLIGHT\r\n"
    "END:VTIMEZONE\r\nEND:VCALENDAR")


def test_vtimezone_rrule_is_not_event_recurrence():
    """iCloud attaches VTIMEZONE to any TZID event, and VTIMEZONE uses RRULE for
    DST. A naive substring check marks every timezone-bearing event recurring."""
    from icloud_mcp.caldav import has_recurrence
    assert "RRULE" in TZ_WITH_VTIMEZONE          # present in the file
    assert has_recurrence(TZ_WITH_VTIMEZONE) is False   # but not on the event


def test_rrule_in_summary_is_not_recurrence():
    from icloud_mcp.caldav import has_recurrence
    ev = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:S1\r\nSUMMARY:RRULE probe\r\nEND:VEVENT\r\nEND:VCALENDAR"
    assert has_recurrence(ev) is False


def test_real_event_rrule_is_detected():
    from icloud_mcp.caldav import has_recurrence
    assert has_recurrence(RECURRING) is True


def test_attendee_detection_is_scoped_and_property_based():
    from icloud_mcp.caldav import has_attendees
    with_att = RECURRING.replace("END:VEVENT", "ATTENDEE;RSVP=TRUE:mailto:a@x.com\r\nEND:VEVENT")
    assert has_attendees(with_att) is True
    assert has_attendees(RECURRING) is False
    mention = RECURRING.replace("SUMMARY:Book club", "SUMMARY:Discuss ATTENDEE list")
    assert has_attendees(mention) is False


# --------------------------------------------------------------------------
# Reminders lists are calendar collections too
# --------------------------------------------------------------------------
# On iCloud, Reminders lists carry resourcetype `calendar,collection,shared-owner`,
# byte-identical to real calendars, and differ ONLY in advertising VTODO. A list
# named "Shopping" or "Errands" showing up as a calendar reads as a broken product,
# and an agent reading such a list can easily conclude they are sync ghosts and
# recommend deleting them, which would destroy the reminder lists.

def test_vevent_collection_is_a_calendar():
    assert holds_events(("VEVENT",)) is True


def test_vtodo_only_collection_is_not():
    assert holds_events(("VTODO",)) is False


def test_mixed_collection_counts_as_a_calendar():
    assert holds_events(("VEVENT", "VFREEBUSY", "VTODO")) is True


def test_absent_component_set_is_kept():
    """RFC 4791: no advertisement means every component. Never hide a calendar."""
    assert holds_events(()) is True


def test_case_is_ignored():
    assert holds_events(("vevent",)) is True
    assert holds_events(("vtodo",)) is False
