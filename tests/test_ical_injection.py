"""Can free text smuggle a new property line into a VEVENT?

Found by security review. _escape_text() escaped "\r\n" and "\n" but
NOT a bare "\r", so a control character in summary/location/description survived
into the emitted iCalendar. A parser that treats a lone CR as a line break then
sees whatever followed it as a NEW PROPERTY.

Why that specifically matters here: ATTENDEE lines make iCloud send real
invitation emails, which is why a restricted deployment (for example a remote
transport, if one is added) can expose create_event with its attendees
parameter removed. An injected ATTENDEE line would put that outbound channel
straight back, reached from an email written by a stranger. The colon-only form needs no ";" or ",", so the
existing escaping of those characters does not block it.

Whether iCloud's parser is lenient about bare CR is NOT established, and is not
testable without writing a real event with a real attendee. The escaping gap is
established, and closing it is free.
"""
from __future__ import annotations

from datetime import date

import pytest

from icloud_mcp.caldav import _escape_text, build_vevent

CR, LF = "\r", "\n"
PAYLOAD = "harmless\rATTENDEE:mailto:attacker@example.com"


def _lines_a_lenient_parser_sees(raw: str) -> list[str]:
    """Split on CRLF, bare LF and bare CR alike."""
    return raw.replace(CR + LF, LF).replace(CR, LF).split(LF)


@pytest.mark.parametrize("ctrl", ["\r", "\n", "\r\n"])
def test_escape_text_removes_every_line_break(ctrl):
    out = _escape_text(f"a{ctrl}b")
    assert CR not in out
    assert LF not in out


@pytest.mark.parametrize("field", ["summary", "location", "description"])
def test_free_text_cannot_inject_an_attendee_line(field):
    kw = {"summary": "Lunch", "location": "", "description": ""}
    kw[field] = PAYLOAD
    ev = build_vevent(start=date(2026, 10, 1), end=date(2026, 10, 2), all_day=True, **kw)
    for line in _lines_a_lenient_parser_sees(ev):
        assert not line.startswith("ATTENDEE"), f"injected via {field}: {line!r}"
        assert not line.startswith("ORGANIZER"), f"injected via {field}: {line!r}"


def test_no_bare_cr_survives_into_the_vevent():
    ev = build_vevent(summary="Lunch", start=date(2026, 10, 1), end=date(2026, 10, 2),
                      all_day=True, description=PAYLOAD)
    assert CR not in ev.replace(CR + LF, LF), "a bare CR reached the iCalendar body"
