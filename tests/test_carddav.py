"""Tests for vCard parsing, North American phone matching and group edits.

No network: every fixture below mirrors the vCard shape iCloud returns, with
synthetic values throughout.
"""
from __future__ import annotations

import pytest

from icloud_mcp.carddav import (
    VCard, parse_vcard, is_north_american, na_tels, add_members,
)

CARD = """BEGIN:VCARD\r
VERSION:3.0\r
PRODID:-//Apple Inc.//macOS 14.0//EN\r
N:;Example Person;;;\r
FN:Example Person\r
ORG:Example Corp;\r
EMAIL;type=INTERNET;type=HOME;type=pref:a@example.com\r
item1.EMAIL;type=INTERNET:b@example.com\r
item1.X-ABLabel:_$!<Other>!$_\r
TEL;type=CELL;type=VOICE;type=pref:+1 212-555-1234\r
REV:2000-01-01T00:00:00Z\r
UID:00000000-0000-0000-0000-000000000001\r
END:VCARD"""

GROUP = """BEGIN:VCARD\r
VERSION:3.0\r
N:Business\r
FN:Business\r
X-ADDRESSBOOKSERVER-KIND:group\r
UID:AAAA1111-2222-3333-4444-555566667777\r
END:VCARD"""


def test_parse_strips_grouping_prefix_and_params():
    c = parse_vcard(CARD)
    assert c is not None
    assert c.uid == "00000000-0000-0000-0000-000000000001"
    assert c.fn == "Example Person"
    assert c.org == "Example Corp"
    # both the plain EMAIL and the item1.EMAIL form must be picked up
    assert sorted(c.emails) == ["a@example.com", "b@example.com"]
    assert c.tels == ["+1 212-555-1234"]
    assert c.is_group is False


def test_parse_folded_lines():
    folded = "BEGIN:VCARD\r\nUID:X1\r\nFN:A Very Long\r\n  Name Here\r\nEND:VCARD"
    c = parse_vcard(folded)
    assert c.fn == "A Very Long Name Here"


def test_parse_requires_uid():
    assert parse_vcard("BEGIN:VCARD\r\nFN:No Uid\r\nEND:VCARD") is None


def test_parse_group_and_members():
    raw = GROUP.replace("END:VCARD",
                        "X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:U1\r\nEND:VCARD")
    c = parse_vcard(raw)
    assert c.is_group is True and c.members == ["U1"]


@pytest.mark.parametrize("tel,expected", [
    ("+1 212-555-1234", True),
    ("+12125551234", True),
    ("+1 (212) 555-1234 x22", True),   # extension tolerated
    ("(212) 555-1234", True),          # no country code, 10 digits
    ("212-555-1234", True),
    ("12125551234", True),             # 11 digits leading 1
    ("+33 1 00 00 00 00", False),      # France
    ("+44 20 7946 0958", False),       # UK
    ("+52 55 0000 0000", False),       # Mexico
    # Common address-book shapes with extensions appended. Without stripping the
    # extension these count as 15 digits and a valid US number is dropped.
    (r"(212)555-0142\;12345", True),
    ("212-555-0142;12345", True),
    ("(212) 555-0142 x1234", True),
    ("212.555.0142 ext. 99", True),
    (r"+33 1 5555 0100\;123", False) ,  # extension must not rescue a non-NA number
    ("555-1234", False),               # too short to judge
    ("", False),
    ("   ", False),
])
def test_is_north_american(tel, expected):
    assert is_north_american(tel) is expected


def test_na_tels_filters_mixed_card():
    c = VCard(uid="x", tels=["+33 1 00 00 00 00", "(646) 555-0000", "+44 20 7946 0958"])
    assert na_tels(c) == ["(646) 555-0000"]


def test_add_members_inserts_before_end_and_dedupes():
    out, n = add_members(GROUP, ["U1", "U2", "U1"])
    assert n == 2
    assert out.count("X-ADDRESSBOOKSERVER-MEMBER") == 2
    lines = out.replace("\r\n", "\n").rstrip("\n").split("\n")
    assert lines[-1] == "END:VCARD"          # members go BEFORE END:VCARD
    assert "urn:uuid:U1" in out and "urn:uuid:U2" in out

    # Re-adding is a no-op, so re-running the job cannot duplicate members.
    again, n2 = add_members(out, ["U1", "U2"])
    assert n2 == 0 and again == out


def test_add_members_preserves_crlf():
    out, _ = add_members(GROUP, ["U9"])
    assert "\r\n" in out
    assert "\n\n" not in out.replace("\r\n", "\n")


def test_add_members_rejects_malformed_group():
    with pytest.raises(ValueError):
        add_members("BEGIN:VCARD\r\nUID:x\r\n", ["U1"])
