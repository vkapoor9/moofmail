"""CalDAV client for iCloud Calendar, plus minimal iCalendar parsing.

Stdlib only. Timezones resolve through `zoneinfo`, so there is still no
third-party dependency anywhere in this project.

iCloud specifics found by probing:
  - Host `https://caldav.icloud.com`, Basic auth with the FULL address (see dav.py).
  - Calendars at the conventional `/{dsid}/calendars/` path; `calendar-home-set`
    is not advertised on the principal.
  - **iCloud supports server-side `<C:expand>`.** A calendar-query carrying an
    expand element returns concrete instances with NO RRULE left, so recurrence
    is never expanded here. Hand-rolled RRULE expansion is where calendar code
    normally goes wrong, and this avoids it entirely.
  - Three DTSTART shapes occur and all must be handled:
        DTSTART;VALUE=DATE:20260807                 all-day
        DTSTART:20260807T212000Z                    UTC
        DTSTART;TZID=America/New_York:20260807T172000 local
"""
from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from html import unescape
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import Config
from .dav import CAL as _CAL, DAV as _DAV, DavClient, unfold_lines

HOST = "https://caldav.icloud.com"

# Components we deliberately ignore: VTODO lives in the "Reminders" calendar and
# is a separate feature, VTIMEZONE is metadata we resolve via zoneinfo instead.
_VEVENT = re.compile(r"BEGIN:VEVENT.*?END:VEVENT", re.S)


# ------------------------------------------------------------------- model
@dataclass
class Event:
    uid: str
    summary: str = ""
    location: str = ""
    description: str = ""
    start: datetime | date | None = None
    end: datetime | date | None = None
    all_day: bool = False
    calendar: str = ""
    href: str = ""
    etag: str = ""
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "summary": self.summary,
            "location": self.location,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "all_day": self.all_day,
            "calendar": self.calendar,
        }


# --------------------------------------------------------------- parsing
def _unescape_text(v: str) -> str:
    """RFC 5545 3.3.11 escaping, applied in an order that keeps \\\\ literal."""
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v):
            nxt = v[i + 1]
            out.append({"n": "\n", "N": "\n", ",": ",", ";": ";", "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _parse_params(name: str) -> dict[str, str]:
    parts = name.split(";")[1:]
    out = {}
    for p in parts:
        if "=" in p:
            k, _, v = p.partition("=")
            out[k.upper()] = v.strip('"')
    return out


def parse_dt(value: str, params: dict[str, str]) -> tuple[datetime | date | None, bool]:
    """Return (value, all_day). Handles the three DTSTART shapes."""
    v = value.strip()
    if params.get("VALUE", "").upper() == "DATE" or re.fullmatch(r"\d{8}", v):
        try:
            return datetime.strptime(v, "%Y%m%d").date(), True
        except ValueError:
            return None, True
    try:
        if v.endswith("Z"):
            return datetime.strptime(v, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc), False
        naive = datetime.strptime(v, "%Y%m%dT%H%M%S")
    except ValueError:
        return None, False
    tzid = params.get("TZID")
    if tzid:
        try:
            return naive.replace(tzinfo=ZoneInfo(tzid)), False
        except (ZoneInfoNotFoundError, ValueError, KeyError):
            return naive, False      # unknown zone: keep it floating, never crash
    return naive, False


def parse_vevent(text: str, calendar: str = "", href: str = "", etag: str = "") -> Event | None:
    """Parse one VEVENT. Returns None without a UID."""
    ev = Event(uid="", calendar=calendar, href=href, etag=etag, raw=text)
    for line in unfold_lines(text):
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.split(";", 1)[0].upper()
        params = _parse_params(name)
        if key == "UID":
            ev.uid = value.strip()
        elif key == "SUMMARY":
            ev.summary = _unescape_text(value)
        elif key == "LOCATION":
            ev.location = _unescape_text(value)
        elif key == "DESCRIPTION":
            ev.description = _unescape_text(value)
        elif key == "DTSTART":
            ev.start, ev.all_day = parse_dt(value, params)
        elif key == "DTEND":
            ev.end, _ = parse_dt(value, params)
    return ev if ev.uid else None


# --------------------------------------------------------------- building
def _escape_text(v: str) -> str:
    """Escape a value for an iCalendar TEXT property.

    The bare "\r" case is not cosmetic. If only "\r\n" and "\n" were escaped,
    a lone CR would survive into the emitted VEVENT. A parser that
    treats a bare CR as a line break then reads whatever followed it as a NEW
    PROPERTY, and "ATTENDEE:mailto:..." needs no ";" or "," so the escaping of
    those characters did not block it.

    That matters because ATTENDEE lines make iCloud send real invitation emails.
    A deployment that exposes create_event without its attendees parameter
    (for example over a restricted remote transport) relies on this escaping:
    injecting an ATTENDEE would put that outbound channel back, driven by text
    from a stranger's email.
    """
    return (str(v or "").replace("\\", "\\\\").replace(";", "\\;")
            .replace(",", "\\,").replace("\r\n", "\\n").replace("\n", "\\n")
            .replace("\r", "\\n"))


def _fold(line: str) -> str:
    """RFC 5545 3.1: fold at 75 octets, continuations start with one space."""
    raw = line.encode("utf-8")
    if len(raw) <= 75:
        return line
    out, cur = [], b""
    for ch in line:
        b = ch.encode("utf-8")
        if len(cur) + len(b) > 73:
            out.append(cur.decode("utf-8"))
            cur = b""
        cur += b
    if cur:
        out.append(cur.decode("utf-8"))
    return "\r\n ".join(out)


def _fmt_dt(v: datetime | date, all_day: bool) -> tuple[str, str]:
    """Return (param_suffix, value)."""
    if all_day or not isinstance(v, datetime):
        return ";VALUE=DATE", v.strftime("%Y%m%d")
    if v.tzinfo is None:
        return "", v.strftime("%Y%m%dT%H%M%S")
    if v.utcoffset() == timedelta(0):
        return "", v.strftime("%Y%m%dT%H%M%SZ")
    tzid = getattr(v.tzinfo, "key", None)
    if tzid:
        return f";TZID={tzid}", v.strftime("%Y%m%dT%H%M%S")
    return "", v.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_vevent(summary: str, start: datetime | date, end: datetime | date,
                 *, uid: str | None = None, location: str = "", description: str = "",
                 all_day: bool = False, attendees: list[str] | None = None,
                 organizer: str | None = None, now: datetime | None = None) -> str:
    """Serialise a VCALENDAR containing one VEVENT.

    ATTENDEE lines make iCloud send real invitation emails, so callers must gate
    on that before writing (see server.create_event).
    """
    uid = uid or str(uuid.uuid4()).upper()
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    sp, sv = _fmt_dt(start, all_day)
    ep, ev_ = _fmt_dt(end, all_day)
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//iCloud MCP//EN",
        "BEGIN:VEVENT",
        f"UID:{uid}", f"DTSTAMP:{stamp}",
        f"DTSTART{sp}:{sv}", f"DTEND{ep}:{ev_}",
        f"SUMMARY:{_escape_text(summary)}",
    ]
    if location:
        lines.append(f"LOCATION:{_escape_text(location)}")
    if description:
        lines.append(f"DESCRIPTION:{_escape_text(description)}")
    if organizer:
        lines.append(f"ORGANIZER:mailto:{organizer}")
    for a in (attendees or []):
        lines.append(f"ATTENDEE;RSVP=TRUE:mailto:{a}")
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(_fold(l) for l in lines) + "\r\n"


# ----------------------------------------------------------------- client
def has_recurrence(raw: str) -> bool:
    """True only if the VEVENT itself carries an RRULE.

    Two traps a naive `"RRULE" in raw` falls into:
      1. iCloud appends a VTIMEZONE component whenever an event uses TZID, and
         VTIMEZONE defines DST transitions with its own RRULE lines. Every
         timezone-bearing event would look recurring.
      2. The literal text can appear inside a SUMMARY or DESCRIPTION.
    So: scope to the VEVENT block, and match RRULE as a property at line start.
    """
    m = re.search(r"BEGIN:VEVENT(.*?)END:VEVENT", raw or "", re.S | re.I)
    if not m:
        return False
    for line in unfold_lines(m.group(1)):
        if re.match(r"^RRULE[;:]", line.strip(), re.I):
            return True
    return False


def has_attendees(raw: str) -> bool:
    """True only if the VEVENT itself carries an ATTENDEE property."""
    m = re.search(r"BEGIN:VEVENT(.*?)END:VEVENT", raw or "", re.S | re.I)
    if not m:
        return False
    return any(re.match(r"^ATTENDEE[;:]", l.strip(), re.I) for l in unfold_lines(m.group(1)))


def update_vevent_lines(raw: str, changes: dict[str, tuple[str, str]]) -> str:
    """Replace properties in a raw VCALENDAR in place, preserving everything else.

    Editing must be surgical rather than regenerative. `parse_vevent` captures only
    a few fields, and reads go through server-side expand which strips RRULE, so
    rebuilding an event from parsed data would silently destroy its recurrence
    rule, alarms and attendees.

    `changes` maps property name -> (param_suffix, value), for example
    {"SUMMARY": ("", "New title"), "DTSTART": (";TZID=America/New_York", "20260805T163000")}.
    A property absent from the source is appended before END:VEVENT.
    """
    if not changes:
        return raw
    eol = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.replace("\r\n", "\n").rstrip("\n").split("\n")

    # Unfold first so a folded SUMMARY is matched and replaced as one unit.
    unfolded: list[str] = []
    for line in lines:
        if line[:1] in (" ", "\t") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)

    remaining = dict(changes)
    out: list[str] = []
    in_event = False
    for line in unfolded:
        upper = line.upper()
        if upper.startswith("BEGIN:VEVENT"):
            in_event = True
        elif upper.startswith("END:VEVENT"):
            for prop, (params, value) in remaining.items():
                out.append(f"{prop}{params}:{value}")
            remaining = {}
            in_event = False
        if in_event and ":" in line:
            prop = line.split(":", 1)[0].split(";", 1)[0].upper()
            if prop in remaining:
                params, value = remaining.pop(prop)
                out.append(f"{prop}{params}:{value}")
                continue
        out.append(line)
    return eol.join(_fold(l) for l in out) + eol


@dataclass
class Calendar:
    name: str
    href: str
    # Components the collection advertises, upper case. Empty means the server
    # did not say, which RFC 4791 treats as "all components".
    components: tuple[str, ...] = ()


def holds_events(components: tuple[str, ...] | list[str]) -> bool:
    """True when a collection can hold events, so it belongs in a calendar list.

    **A Reminders list is a real CalDAV `calendar` collection.** On iCloud it
    carries a `resourcetype` of `calendar,collection,shared-owner`, identical to
    the real calendars, and differs only in advertising `VTODO` instead of
    `VEVENT`. Filtering on resourcetype therefore cannot separate them, and
    listing reminder lists such as "Shopping" as calendars reads as a broken product.

    A collection that advertises nothing is KEPT. RFC 4791 says an absent
    `supported-calendar-component-set` means every component is supported, and
    hiding a real calendar is far worse than showing a shopping list.
    """
    return not components or "VEVENT" in {c.upper() for c in components}


class CalDavClient(DavClient):
    HOST = HOST
    HOME_NS = "urn:ietf:params:xml:ns:caldav"
    HOME_PROP = "calendar-home-set"
    HOME_PATH = "calendars"

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self._calendars: list[Calendar] | None = None

    def calendars(self) -> list[Calendar]:
        if self._calendars is not None:
            return self._calendars
        body = ('<?xml version="1.0"?>'
                '<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
                "<d:prop><d:displayname/><d:resourcetype/>"
                "<c:supported-calendar-component-set/></d:prop></d:propfind>").encode()
        url = self.home()
        code, txt = self.request("PROPFIND", url, body, depth="1",
                                 ctype="application/xml; charset=utf-8")
        if code != 207:
            raise RuntimeError(f"CalDAV calendar list failed: HTTP {code}")
        out = []
        for resp in self.responses(txt):
            rt = resp.find(f".//{_DAV}resourcetype")
            kinds = [c.tag.split("}")[-1] for c in (rt if rt is not None else [])]
            name = self.text_of(resp.find(f".//{_DAV}displayname")).strip()
            href = self.text_of(resp.find(f"{_DAV}href"))
            comps = tuple(c.get("name", "").upper()
                          for c in resp.findall(f".//{_CAL}comp") if c.get("name"))
            # resourcetype alone is not enough: Reminders lists are `calendar`
            # collections too, and only the component set separates them. The
            # home collection and the schedule inbox/outbox lack `calendar`
            # entirely, which is what already keeps them out.
            if "calendar" in kinds and name and href and holds_events(comps):
                out.append(Calendar(name=name, href=href, components=comps))
        self._calendars = out
        return out

    def events(self, start: datetime, end: datetime,
               include: list[str] | None = None, workers: int = 8) -> list[Event]:
        """Expanded events in [start, end) across the selected calendars.

        `<C:expand>` makes the server return concrete instances of recurring
        events, so no RRULE handling is needed here.
        """
        s = start.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        e = end.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        body = (
            '<?xml version="1.0"?>'
            '<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
            f'<d:prop><c:calendar-data><c:expand start="{s}" end="{e}"/></c:calendar-data></d:prop>'
            '<c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT">'
            f'<c:time-range start="{s}" end="{e}"/>'
            "</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"
        ).encode()

        wanted = self.calendars()
        if include:
            keep = {n.strip().lower() for n in include}
            wanted = [c for c in wanted if c.name.strip().lower() in keep]

        def one(cal: Calendar) -> list[Event]:
            code, txt = self.request("REPORT", self.url(cal.href), body, depth="1",
                                     ctype="application/xml; charset=utf-8")
            if code != 207:
                return []
            found = []
            for resp in self.responses(txt):
                data = resp.find(f".//{_CAL}calendar-data")
                if data is None or not (data.text or "").strip():
                    continue
                href = self.text_of(resp.find(f"{_DAV}href"))
                etag = self.text_of(resp.find(f".//{_DAV}getetag"))
                for block in _VEVENT.findall(unescape(data.text)):
                    ev = parse_vevent(block, calendar=cal.name, href=href, etag=etag)
                    if ev:
                        found.append(ev)
            return found

        out: list[Event] = []
        # Fetching a dozen or more calendars serially takes seconds; in parallel, about one.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for chunk in pool.map(one, wanted):
                out.extend(chunk)
        out.sort(key=lambda ev: (ev.start is None, _sort_key(ev.start)))
        return out

    def find_by_uid(self, uid: str, days: int = 400,
                    include: list[str] | None = None) -> Event | None:
        """Locate an event by UID within a window around today."""
        from datetime import datetime as _dt
        now = _dt.now(timezone.utc)
        for ev in self.events(now - timedelta(days=days), now + timedelta(days=days),
                              include=include):
            if ev.uid == uid:
                return ev
        return None

    def get_raw(self, href: str) -> tuple[bool, str]:
        """Fetch the UNEXPANDED source of one event.

        Must not come from events(): that uses <C:expand>, which returns concrete
        instances with RRULE stripped. Editing from expanded data would drop the
        recurrence rule.
        """
        code, txt = self.request("GET", self.url(href))
        return code == 200, txt

    def delete_event(self, href: str, etag: str | None = None) -> tuple[bool, str]:
        """Delete an event. Irreversible: CalDAV has no calendar Trash."""
        extra = {"If-Match": etag} if etag else {}
        code, txt = self.request("DELETE", self.url(href), extra=extra)
        ok = code in (200, 204)
        return ok, f"HTTP {code}" + ("" if ok else f": {txt[:200]}")

    def put_event(self, calendar_href: str, uid: str, ics: str,
                  etag: str | None = None) -> tuple[bool, str]:
        """Create or replace an event. If-Match guards against a concurrent edit."""
        url = f"{self.url(calendar_href.rstrip('/'))}/{uid}.ics"
        extra = {"If-Match": etag} if etag else {}
        code, txt = self.request("PUT", url, ics.encode("utf-8"),
                                 ctype="text/calendar; charset=utf-8", extra=extra)
        ok = code in (200, 201, 204)
        return ok, f"HTTP {code}" + ("" if ok else f": {txt[:200]}")


def _sort_key(v):
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).replace(tzinfo=None)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day)
    return datetime.max
