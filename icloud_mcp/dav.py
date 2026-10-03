"""Shared WebDAV plumbing for the iCloud CardDAV and CalDAV clients.

Stdlib only, matching the rest of this project.

iCloud specifics that apply to both services:
  - HTTP Basic auth with the **full** Apple Account address. The short IMAP
    username returns 401. SMTP behaves the same way; IMAP is the odd one out.
  - The `*-home-set` property IS advertised, but only on the PRINCIPAL URL
    (`/{dsid}/principal/`), not on the root that discovery starts from. An
    earlier version assumed it was not advertised at all, because it was looked
    for at the wrong URL, which sent every request to the generic host.
  - **Each account is served from a PARTITIONED host.** Each account lives on
    its own `pNN-caldav.icloud.com` host (different accounts get different NN),
    with a matching `pNN-contacts` host for CardDAV. The generic
    `caldav.icloud.com` currently proxies, so building URLs against it appears
    to work. When it stops proxying it does NOT error: it returns HTTP 207 with
    an empty multistatus, a valid successful response carrying nothing,
    indistinguishable from an empty calendar.
    Resolve every relative href with `url()`, never against the constant.
"""
from __future__ import annotations

import base64
import re
import urllib.error
import urllib.parse
import urllib.request
from xml.etree import ElementTree as ET

from .config import Config
from .keychain import get_password

DAV = "{DAV:}"
CARD = "{urn:ietf:params:xml:ns:carddav}"
CAL = "{urn:ietf:params:xml:ns:caldav}"

_PRINCIPAL_HREF = re.compile(r"^/?(\d+)/principal/?$")


def unfold_lines(text: str) -> list[str]:
    """Unfold a vCard or iCalendar body.

    Both formats use the same continuation rule: a line beginning with a space
    or tab continues the previous one.
    """
    out: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line[:1] in (" ", "\t") and out:
            out[-1] += line[1:]
        else:
            out.append(line)
    return out


class DavClient:
    """Authenticated DAV requests plus principal discovery."""

    HOST = ""          # subclasses set this: the GENERIC host, discovery only
    # The home-set property to read off the principal, and the conventional
    # path to fall back to when it is not advertised.
    HOME_NS = ""
    HOME_PROP = ""
    HOME_PATH = ""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        # The FULL address, not cfg.imap_username. The short form 401s.
        self._auth = base64.b64encode(
            f"{cfg.address}:{get_password(cfg.keychain_account, cfg.keychain_service)}".encode()
        ).decode()
        self._dsid: str | None = None
        self._home: str | None = None

    def request(self, method: str, url: str, body: bytes | None = None,
                depth: str | None = None, ctype: str | None = None,
                extra: dict[str, str] | None = None,
                timeout: int = 120) -> tuple[int, str]:
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Authorization", f"Basic {self._auth}")
        if depth is not None:
            req.add_header("Depth", depth)
        if ctype:
            req.add_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.getcode(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def dsid(self) -> str:
        """The numeric account id from the current-user-principal href."""
        if self._dsid:
            return self._dsid
        body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:">'
                "<d:prop><d:current-user-principal/></d:prop></d:propfind>").encode()
        code, txt = self.request("PROPFIND", self.HOST + "/", body, depth="0",
                                 ctype="application/xml; charset=utf-8")
        if code != 207:
            raise RuntimeError(f"{self.HOST} principal lookup failed: HTTP {code}")
        # Parse rather than regex: CardDAV and CalDAV format this response
        # differently (whitespace and element nesting), and a regex that matches
        # one silently fails on the other.
        for el in ET.fromstring(txt).iter(f"{DAV}href"):
            m = _PRINCIPAL_HREF.search(el.text or "")
            if m:
                self._dsid = m.group(1)
                return self._dsid
        raise RuntimeError(f"could not find the principal href at {self.HOST}")

    def home(self) -> str:
        """The collection home for this account, DISCOVERED from the principal.

        Discovered rather than constructed because iCloud partitions accounts
        across hosts and names the right one only here. Cached: `events()` fans
        out across a thread pool and must not re-discover per calendar.
        """
        if self._home:
            return self._home
        body = ('<?xml version="1.0"?>'
                f'<d:propfind xmlns:d="DAV:" xmlns:h="{self.HOME_NS}">'
                f"<d:prop><h:{self.HOME_PROP}/></d:prop></d:propfind>").encode()
        # Discovery itself must start at the generic host; it is what we know.
        code, txt = self.request("PROPFIND", f"{self.HOST}/{self.dsid()}/principal/",
                                 body, depth="0", ctype="application/xml; charset=utf-8")
        found = ""
        if code == 207:
            try:
                for el in ET.fromstring(txt).iter(f"{{{self.HOME_NS}}}{self.HOME_PROP}"):
                    for h in el.iter(f"{DAV}href"):
                        if (h.text or "").strip().startswith("http"):
                            found = (h.text or "").strip()
                            break
                    if found:
                        break
            except ET.ParseError:
                found = ""
        # Degrade to the conventional path rather than raising. A missing
        # home-set must not take every calendar and contacts tool down.
        fallback = f"{self.HOST}/{self.dsid()}/{self.HOME_PATH}/"
        self._home = (found or fallback).rstrip("/") + "/"
        return self._home

    @property
    def origin(self) -> str:
        """Scheme and host actually serving THIS account (may be partitioned)."""
        p = urllib.parse.urlsplit(self.home())
        return f"{p.scheme}://{p.netloc}"

    def url(self, href: str) -> str:
        """Resolve a server-relative href against this account's own origin.

        Never `HOST + href`. The constant is the generic host, and a relative
        href belongs to whichever partition serves this account.
        """
        if href.startswith("http://") or href.startswith("https://"):
            return href
        return self.origin + href

    @staticmethod
    def responses(xml: str) -> list[ET.Element]:
        """`{DAV:}response` elements from a multistatus body."""
        return ET.fromstring(xml).findall(f"{DAV}response")

    @staticmethod
    def text_of(el: ET.Element | None) -> str:
        return (el.text or "") if el is not None else ""
