"""Data models and header helpers shared across iCloud MCP.

Kept dependency-free (stdlib only) so it is trivially unit-testable without a
live IMAP connection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone


@dataclass
class Message:
    """A normalized mail message summary/detail.

    Populated from IMAP fetches. `headers` keys are lowercased for stable lookup.
    """
    uid: int
    from_addr: str = ""
    from_name: str = ""
    to: str = ""
    subject: str = ""
    date: datetime | None = None
    snippet: str = ""
    flags: tuple[str, ...] = ()
    headers: dict[str, str] = field(default_factory=dict)
    body_text: str | None = None
    attachments: list[str] = field(default_factory=list)

    @property
    def seen(self) -> bool:
        return "\\Seen" in self.flags

    @property
    def is_bulk(self) -> bool:
        """True for mailing-list / bulk mail.

        Signals: a List-Unsubscribe header, or Precedence: bulk|list|junk,
        or a List-Id header. These are the standard markers of non-personal mail.
        """
        h = self.headers
        if "list-unsubscribe" in h or "list-id" in h:
            return True
        prec = h.get("precedence", "").strip().lower()
        return prec in {"bulk", "list", "junk"}

    @property
    def is_machine_bulk(self) -> bool:
        """True for platform-sent marketing that omits List-Unsubscribe.

        Requires BOTH a VERP return-path AND an ESP fingerprint header, then
        exempts anything that looks transactional. This is a SOFT signal: it
        only demotes score in triage, it never removes a message, because the
        same platforms carry login links and receipts.
        """
        h = self.headers
        rp = h.get("return-path", "").strip().strip("<>")
        local = rp.split("@")[0] if "@" in rp else rp
        if not (local and _VERP_RE.match(local)):
            return False
        if not any(k in h for k in _ESP_HEADERS):
            return False
        return not _TRANSACTIONAL_RE.search(self.subject or "")

    def to_summary(self) -> dict:
        """Compact JSON-safe dict for tool output (no full body).

        `snippet` is omitted when empty, which is every listing. Summaries are
        built from a headers-only fetch on purpose, so there is no body to take
        a snippet from; carrying `"snippet": ""` on every row of a 200-message
        listing is pure noise and pure token cost. The key still appears when
        something has actually populated it.
        """
        out = {
            "uid": self.uid,
            "from": self.from_addr,
            "from_name": self.from_name,
            "subject": self.subject,
            "date": self.date.isoformat() if self.date else None,
            "unread": not self.seen,
            "bulk": self.is_bulk,
        }
        if self.snippet:
            out["snippet"] = self.snippet
        return out


# --- machine/marketing detection (soft signal, demotes but never hides) ---
# VERP bounce addresses: no human MUA sends with these.
_VERP_RE = re.compile(r"^(bounces?[-+]|bounce-|msprvs1=|prvs=|srs0=)", re.I)

# Headers stamped by bulk-sending platforms (SendGrid, Mailgun, SES, Mailchimp...).
_ESP_HEADERS = (
    "x-sg-eid", "x-sg-id", "x-mailgun-sid", "x-ses-outgoing", "feedback-id",
    "x-campaign", "x-campaignid", "x-mandrill-user", "x-mc-user", "x-csa-complaints",
)

# Transactional mail rides the SAME platforms as marketing. Login links (such as
# a Claude Console sign-in link), receipts, bank alerts and Apple security
# notices commonly carry VERP + SendGrid/SES fingerprints. These keywords
# RESCUE a message from demotion; they never hide anything.
_TRANSACTIONAL_RE = re.compile(
    r"secure link|sign[- ]?in|log[- ]?in|verification|verify|one[- ]?time|"
    r"password|passcode|2fa|security|receipt|invoice|statement|payment|"
    r"transaction|refund|renewal|renewed|expir|shipped|delivered|order\s*#|"
    r"appointment|confirm",
    re.I,
)


# RFC 5322 2.2.3: a folded header is CRLF followed by at least one WSP, and
# unfolding removes the CRLF while keeping the WSP.
_FOLD = re.compile(r"\r?\n(?=[ \t])")
# Anything left is a bare CR/LF, which is not a legal fold. Collapse rather than
# trust it: an unfolded newline in a subject injects a second line into the
# plain-text brief.
_STRAY_EOL = re.compile(r"[\r\n]+")


def decode_mime_header(raw: str | None) -> str:
    """Decode an RFC 2047 encoded-word header into plain text.

    Handles Q- and B-encoding, mixed charsets, and headers folded across lines.
    Never raises: a malformed encoded-word comes back as-is rather than blowing
    up a whole inbox listing.

    Unfolding must happen BEFORE decoding. `make_header` unfolds as a side effect
    of joining encoded words, but leaves folding untouched in plain text, so long
    unencoded subjects kept their CRLF and corrupted the brief and search.
    This is the read-side twin of `smtp_send.clean_header`.
    """
    if not raw:
        return ""
    raw = _STRAY_EOL.sub(" ", _FOLD.sub("", str(raw)))
    try:
        return str(make_header(decode_header(raw)))
    except (UnicodeDecodeError, LookupError, ValueError):
        return raw


def parse_from(raw_from: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a raw From header value."""
    name, addr = parseaddr(raw_from or "")
    return decode_mime_header(name).strip(), addr.strip().lower()


def parse_date(raw_date: str) -> datetime | None:
    """Parse an RFC 2822 Date header into an aware datetime (UTC if naive)."""
    if not raw_date:
        return None
    try:
        dt = parsedate_to_datetime(raw_date)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def normalize_headers(items) -> dict[str, str]:
    """Lowercase-key a header mapping/iterable of (k, v) pairs.

    Last value wins for duplicate keys (fine for the headers we care about).
    """
    out: dict[str, str] = {}
    if items is None:
        return out
    pairs = items.items() if hasattr(items, "items") else items
    for k, v in pairs:
        out[str(k).strip().lower()] = str(v).strip()
    return out
