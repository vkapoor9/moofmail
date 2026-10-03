"""Which HOST do DAV requests actually go to?

The bug these guard: iCloud serves each account from a PARTITIONED host and
advertises it in the `*-home-set` property on the principal. In practice every
account is partitioned, each on its own host:

    main -> https://pNN-caldav.icloud.com:443/<dsid>/calendars/
    work -> https://pMM-caldav.icloud.com:443/<dsid>/calendars/

Both clients ignored that and CONSTRUCTED every URL against the generic host
(caldav.icloud.com). That works only while the generic host proxies. When it
does not, the result is HTTP 207 with an empty multistatus, a valid successful response carrying nothing, indistinguishable
from a calendar with no events.

No network: `request` is replaced with canned responses recording every URL.
"""
from __future__ import annotations

import pytest

from icloud_mcp.caldav import CalDavClient
from icloud_mcp.carddav import CardDavClient
from icloud_mcp.config import Config

DSID = "9999"

PRINCIPAL_XML = (
    '<?xml version="1.0"?><multistatus xmlns="DAV:"><response>'
    f"<href>/{DSID}/principal/</href><propstat><prop>"
    f"<current-user-principal><href>/{DSID}/principal/</href></current-user-principal>"
    "</prop></propstat></response></multistatus>"
)

# Shape mirrors the response iCloud returns, with a synthetic dsid and partition number.
CAL_HOME_XML = (
    '<?xml version="1.0" encoding="UTF-8"?><multistatus xmlns="DAV:">'
    f'<response xmlns="DAV:"><href>/{DSID}/principal/</href><propstat><prop>'
    '<calendar-home-set xmlns="urn:ietf:params:xml:ns:caldav">'
    f'<href xmlns="DAV:">https://p42-caldav.icloud.com:443/{DSID}/calendars/</href>'
    "</calendar-home-set></prop><status>HTTP/1.1 200 OK</status></propstat>"
    "</response></multistatus>"
)

CARD_HOME_XML = (
    '<?xml version="1.0" encoding="UTF-8"?><multistatus xmlns="DAV:">'
    f'<response xmlns="DAV:"><href>/{DSID}/principal/</href><propstat><prop>'
    '<addressbook-home-set xmlns="urn:ietf:params:xml:ns:carddav">'
    f'<href xmlns="DAV:">https://p42-contacts.icloud.com:443/{DSID}/carddavhome/</href>'
    "</addressbook-home-set></prop><status>HTTP/1.1 200 OK</status></propstat>"
    "</response></multistatus>"
)

NO_HOME_XML = (
    '<?xml version="1.0"?><multistatus xmlns="DAV:"><response>'
    f"<href>/{DSID}/principal/</href><propstat>"
    "<status>HTTP/1.1 404 Not Found</status></propstat></response></multistatus>"
)


@pytest.fixture
def client(monkeypatch):
    """Build a real client with the Keychain stubbed, then can its responses."""
    monkeypatch.setattr("icloud_mcp.dav.get_password", lambda *a, **k: "app-specific-pw")

    def _make(cls, home_xml):
        c = cls(Config(address="someone@me.com"))
        c.calls = []

        def fake_request(method, url, body=None, **kw):
            c.calls.append((method, url))
            if "/principal/" in url and b"home-set" in (body or b""):
                return 207, home_xml
            if url.rstrip("/").endswith(c.HOST.rstrip("/")):
                return 207, PRINCIPAL_XML
            if method == "PROPFIND" and body and b"current-user-principal" in body:
                return 207, PRINCIPAL_XML
            return 207, "<multistatus xmlns='DAV:'></multistatus>"

        c.request = fake_request
        return c

    return _make


# ------------------------------------------------------------------ origin
def test_caldav_origin_comes_from_the_advertised_home_not_the_generic_host(client):
    c = client(CalDavClient, CAL_HOME_XML)
    assert "p42-caldav.icloud.com" in c.origin
    assert c.origin != c.HOST


def test_carddav_origin_comes_from_the_advertised_home(client):
    c = client(CardDavClient, CARD_HOME_XML)
    assert "p42-contacts.icloud.com" in c.origin


def test_a_relative_href_resolves_against_the_partition_host(client):
    """The live bug: HOST + href sent every read and write to the generic host."""
    c = client(CalDavClient, CAL_HOME_XML)
    assert c.url(f"/{DSID}/calendars/work/abc.ics") == \
        f"https://p42-caldav.icloud.com:443/{DSID}/calendars/work/abc.ics"


def test_an_absolute_href_is_passed_through_untouched(client):
    c = client(CalDavClient, CAL_HOME_XML)
    absolute = "https://p42-caldav.icloud.com:443/x/y.ics"
    assert c.url(absolute) == absolute


def test_home_is_discovered_only_once(client):
    """Discovery costs a round trip, and events() fans out across threads."""
    c = client(CalDavClient, CAL_HOME_XML)
    c.origin, c.origin, c.origin
    home_lookups = [u for m, u in c.calls if "/principal/" in u]
    assert len(home_lookups) <= 2   # dsid discovery plus one home-set lookup


def test_falls_back_to_the_conventional_path_when_nothing_is_advertised(client):
    """iCloud must not be trusted to keep advertising it. Degrade, do not raise."""
    c = client(CalDavClient, NO_HOME_XML)
    assert c.home() == f"{c.HOST}/{DSID}/calendars/"
    assert c.origin == c.HOST


def test_carddav_addressbook_sits_under_the_discovered_home(client):
    """The advertised home is .../carddavhome/; the cards live in .../card/."""
    c = client(CardDavClient, CARD_HOME_XML)
    assert c.addressbook_url() == f"https://p42-contacts.icloud.com:443/{DSID}/carddavhome/card/"


def test_no_client_method_still_builds_a_url_from_the_bare_constant():
    """Structural guard: `HOST + href` is the exact shape of the live bug.

    A behavioural test cannot catch a reintroduction, because the generic host
    currently answers correctly. Only the shape is checkable.
    """
    import inspect
    from icloud_mcp import caldav, carddav

    offenders = []
    for mod in (caldav, carddav):
        for line_no, line in enumerate(inspect.getsource(mod).splitlines(), 1):
            code = line.split("#", 1)[0]
            if "HOST +" in code or "{HOST}" in code:
                offenders.append(f"{mod.__name__}:{line_no}: {line.strip()}")
    assert offenders == [], "build URLs with self.url()/self.home(), not the constant:\n" + \
        "\n".join(offenders)
