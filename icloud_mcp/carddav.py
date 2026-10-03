"""CardDAV client for iCloud Contacts, plus minimal vCard parsing.

Deliberately stdlib-only, matching the rest of this project: no third-party
CardDAV or vCard library is pulled in. Reading vCards is far simpler than
writing a general-purpose parser, and this only needs the fields we use.

iCloud specifics learned by probing:
  - Host: https://contacts.icloud.com
  - Auth: HTTP Basic with the FULL Apple Account address, e.g. user@icloud.com.
    NOT the short IMAP username, which returns 401. (SMTP behaves the same way,
    IMAP is the odd one out.)
  - `addressbook-home-set` is NOT advertised on the principal. The address book
    lives at the conventional /{dsid}/carddavhome/card/ path, where dsid comes
    from the current-user-principal href.
  - REPORT addressbook-query returns every card in one response, with the vCard
    body XML-escaped (&#13; for CR, &amp;, &lt;). It must be unescaped.
  - Groups are cards carrying X-ADDRESSBOOKSERVER-KIND:group, with members as
    X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:<UID> lines.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html import unescape

from .config import Config
from .dav import CARD as _CARD, DAV as _DAV, DavClient, unfold_lines

HOST = "https://contacts.icloud.com"


# ---------------------------------------------------------------- vCard model
@dataclass
class VCard:
    uid: str
    fn: str = ""
    org: str = ""
    emails: list[str] = field(default_factory=list)
    tels: list[str] = field(default_factory=list)
    is_group: bool = False
    members: list[str] = field(default_factory=list)
    href: str = ""
    etag: str = ""
    raw: str = ""


def parse_vcard(text: str, href: str = "", etag: str = "") -> VCard | None:
    """Parse the handful of fields we care about. Returns None without a UID."""
    card = VCard(uid="", href=href, etag=etag, raw=text)
    for line in unfold_lines(text):
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        # Strip grouping prefix (item1.EMAIL) and parameters (EMAIL;type=HOME).
        base = name.split(";", 1)[0]
        if "." in base:
            base = base.split(".", 1)[1]
        key = base.upper()
        value = value.strip()
        if key == "UID":
            card.uid = value
        elif key == "FN":
            card.fn = value
        elif key == "ORG":
            card.org = value.rstrip(";").replace(";", " ").strip()
        elif key == "EMAIL" and value:
            card.emails.append(value)
        elif key == "TEL" and value:
            card.tels.append(value)
        elif key == "X-ADDRESSBOOKSERVER-KIND" and value.lower() == "group":
            card.is_group = True
        elif key == "X-ADDRESSBOOKSERVER-MEMBER" and value:
            card.members.append(value.split("urn:uuid:")[-1])
    return card if card.uid else None


# ------------------------------------------------------------- phone matching
# vCard stores an extension after a literal backslash-semicolon, and address books
# also use ';', 'x' or 'ext'. Without stripping these, "(212)555-0142\;12345" counts
# as 15 digits and a valid US number gets thrown away.
# Note on the 'x' branch: \bx\b does NOT match "x1234", because x and 1 are both
# word characters so there is no boundary between them. Match an x that sits
# between a digit/space and a digit instead.
_EXT_SPLIT = re.compile(r"\\;|;|#|\bext\.?|(?<=[\d\s)])x(?=[\s.]*\d)", re.I)


def is_north_american(tel: str) -> bool:
    """True for a North American Numbering Plan number (+1: US/Canada/Caribbean).

    Explicit non-+1 country codes are excluded. A number with no country code is
    treated as North American when it has 10 digits (or 11 starting with 1),
    which is how a local number is normally stored in a US address book.
    Extensions are stripped before counting.
    """
    raw = (tel or "").strip()
    if not raw:
        return False
    base = _EXT_SPLIT.split(raw, maxsplit=1)[0].strip()
    digits = re.sub(r"\D", "", base)
    if raw.startswith("+"):
        return digits.startswith("1") and len(digits) >= 11
    if len(digits) == 10:
        return True
    if len(digits) == 11 and digits.startswith("1"):
        return True
    return False


def na_tels(card: VCard) -> list[str]:
    return [t for t in card.tels if is_north_american(t)]


# ----------------------------------------------------------------- DAV client
class CardDavClient(DavClient):
    HOST = HOST
    HOME_NS = "urn:ietf:params:xml:ns:carddav"
    HOME_PROP = "addressbook-home-set"
    HOME_PATH = "carddavhome"

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self._addressbook: str | None = None


    def addressbook_url(self) -> str:
        """The address book collection URL.

        The advertised home is `.../carddavhome/`; the cards live one level
        down in `card/`. Built off home() so it lands on this account's
        partition rather than the generic host.
        """
        if not self._addressbook:
            self._addressbook = self.home() + "card/"
        return self._addressbook

    def fetch_all(self) -> list[VCard]:
        """Every card in the address book, contacts and groups alike."""
        body = ('<?xml version="1.0"?>'
                '<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">'
                "<d:prop><d:getetag/><c:address-data/></d:prop></c:addressbook-query>").encode()
        code, txt = self.request("REPORT", self.addressbook_url(), body, depth="1",
                                  ctype="application/xml; charset=utf-8")
        if code != 207:
            raise RuntimeError(f"CardDAV addressbook-query failed: HTTP {code}")
        out: list[VCard] = []
        for resp in self.responses(txt):
            href_el = resp.find(f"{_DAV}href")
            etag_el = resp.find(f".//{_DAV}getetag")
            data_el = resp.find(f".//{_CARD}address-data")
            if data_el is None or not (data_el.text or "").strip():
                continue
            card = parse_vcard(
                unescape(data_el.text),
                href=href_el.text if href_el is not None else "",
                etag=(etag_el.text or "") if etag_el is not None else "",
            )
            if card:
                out.append(card)
        return out

    def put_card(self, href: str, vcard_text: str, etag: str | None = None) -> tuple[bool, str]:
        """Write a card back. Passes If-Match so a concurrent edit cannot be clobbered."""
        extra = {"If-Match": etag} if etag else {}
        code, txt = self.request("PUT", self.url(href), vcard_text.encode("utf-8"),
                                  ctype="text/vcard; charset=utf-8", extra=extra)
        ok = code in (200, 201, 204)
        return ok, f"HTTP {code}" + ("" if ok else f": {txt[:200]}")


# --------------------------------------------------------------- group edits
def add_members(group_raw: str, uids: list[str]) -> tuple[str, int]:
    """Return (new vCard text, number added), skipping UIDs already present.

    Members are inserted before END:VCARD, matching the line ending already used
    by the card so the file stays internally consistent.
    """
    existing = set(re.findall(r"X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:([^\r\n]+)", group_raw))
    fresh = [u for u in dict.fromkeys(uids) if u and u not in existing]
    if not fresh:
        return group_raw, 0
    eol = "\r\n" if "\r\n" in group_raw else "\n"
    lines = group_raw.replace("\r\n", "\n").rstrip("\n").split("\n")
    end = len(lines) - 1
    while end >= 0 and not lines[end].upper().startswith("END:VCARD"):
        end -= 1
    if end < 0:
        raise ValueError("group vCard has no END:VCARD")
    block = [f"X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:{u}" for u in fresh]
    lines[end:end] = block
    return eol.join(lines) + eol, len(fresh)
