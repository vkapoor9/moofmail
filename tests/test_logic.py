"""Unit tests for iCloud MCP's credential-independent logic."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from icloud_mcp.config import parse_config, parse_accounts, ConfigError
from icloud_mcp.smtp_send import MailSender
from icloud_mcp.models import (
    Message, parse_from, parse_date, normalize_headers, decode_mime_header,
)
from icloud_mcp.rules import priority_for, cleanup_action_for
from icloud_mcp.triage import rank_inbox, format_brief, format_brief_html
from icloud_mcp.unsubscribe import parse_unsubscribe


NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)


def mk(uid, frm="a@x.com", subj="hi", bulk=False, seen=False, days_old=0, extra=None):
    headers = {}
    if bulk:
        headers["list-unsubscribe"] = "<https://x.com/u>"
    if extra:
        headers.update(extra)
    name, addr = parse_from(frm)
    return Message(
        uid=uid, from_addr=addr, from_name=name, subject=subj,
        date=NOW - timedelta(days=days_old),
        flags=("\\Seen",) if seen else (), headers=headers,
    )


# ---- models ----
def test_parse_from_and_bulk():
    n, a = parse_from("Bob Smith <Bob@Foo.com>")
    assert n == "Bob Smith" and a == "bob@foo.com"
    assert mk(1, bulk=True).is_bulk is True
    assert mk(1, bulk=False).is_bulk is False
    assert Message(uid=2, headers={"precedence": "bulk"}).is_bulk is True


def test_parse_date_naive_gets_utc():
    dt = parse_date("Wed, 15 Jul 2026 09:00:00 -0000")
    assert dt is not None and dt.tzinfo is not None
    assert parse_date("garbage") is None
    assert parse_date("") is None


def test_normalize_headers_lowercases():
    h = normalize_headers([("List-Unsubscribe", "<x>"), ("Subject", "Hi")])
    assert h["list-unsubscribe"] == "<x>" and h["subject"] == "Hi"


def test_decode_mime_header_qp_folded():
    # Header shape: Q-encoded and folded across two lines.
    raw = (
        "=?UTF-8?Q?An_app-specific_password_was_g?=\r\n"
        " =?UTF-8?Q?enerated_for_your_Apple=C2=A0Account?="
    )
    assert decode_mime_header(raw) == "An app-specific password was generated for your Apple\xa0Account"


def test_decode_mime_header_base64_emoji():
    # Header shape: base64 utf-8 with emoji, an em dash and a middle dot.
    raw = (
        "=?utf-8?b?8J+TpiBXZWVrbHkgRGlnZXN0IOKAlCBJc3N1ZSAjNyAoMyBuZXcgwrcg"
        "MCBhcmNoaXZlZCk=?="
    )
    assert decode_mime_header(raw) == "📦 Weekly Digest — Issue #7 (3 new · 0 archived)"


def test_decode_mime_header_unfolds_plain_folded_subject():
    """RFC 5322 folding on UNENCODED text. make_header only unfolds encoded words,
    so plain long subjects (many automated notifications) kept their CRLF."""
    raw = "Delivery scheduled | Order #0000, arriving Friday between 3:15 and 5:15\r\n PM"
    out = decode_mime_header(raw)
    assert "\r" not in out and "\n" not in out
    assert out.endswith("5:15 PM")          # unfolding keeps the leading space


def test_decode_mime_header_unfolds_across_encoded_words():
    assert decode_mime_header("=?UTF-8?Q?Caf=C3=A9?=\r\n =?UTF-8?Q?_Meeting?=") == "Café Meeting"


def test_decode_mime_header_collapses_bare_newline():
    """A bare CRLF with no trailing whitespace is not a legal fold. Letting it
    through would let a subject inject a second line into the plain-text brief."""
    out = decode_mime_header("Subject one\r\nInjected: header")
    assert "\r" not in out and "\n" not in out
    assert "Subject one" in out and "Injected" in out


def test_decode_mime_header_passthrough_and_garbage():
    assert decode_mime_header("Plain ASCII subject") == "Plain ASCII subject"
    assert decode_mime_header("") == ""
    assert decode_mime_header(None) == ""
    # Malformed encoded-word must not raise; worst case it comes back untouched.
    assert decode_mime_header("=?UTF-8?Q?broken") == "=?UTF-8?Q?broken"


def test_parse_from_decodes_display_name():
    n, a = parse_from("=?UTF-8?Q?Jos=C3=A9_Garc=C3=ADa?= <Jose@Foo.com>")
    assert n == "José García" and a == "jose@foo.com"


# ---- machine/marketing detection (soft demotion signal) ----
# Header SHAPES below mirror typical marketing and transactional mail; every identifying value
# (subscriber ids, recipient aliases) is synthetic. Do not paste real headers
# into tests, they end up in git.

MARKETING_H = {
    "return-path": "<bounces+0000000-0000-user=example.com@em0000.shop.example.com>",
    "x-sg-eid": "abc123",
    "x-sg-id": "def456",
}
ANTHROPIC_LOGIN_H = dict(MARKETING_H)  # same VERP + SendGrid fingerprint
HOSTING_H = {"return-path": "<bounces-9912@info.host.example.com>"}  # VERP, no ESP


def test_machine_bulk_flags_marketing_esp():
    m = Message(uid=1, from_addr="newsletter@shop.example.com",
                subject="Spring Sale: 20% Off Everything", headers=MARKETING_H)
    assert m.is_machine_bulk is True
    assert m.is_bulk is False  # no List-Unsubscribe: hard exclusion still won't fire


def test_machine_bulk_exempts_transactional():
    # Same ESP fingerprint as the marketing fixture, but this is a time-sensitive login link.
    m = Message(uid=2, from_addr="no-reply-xyz@mail.anthropic.com",
                subject="Your secure link to the Claude Console is here",
                headers=ANTHROPIC_LOGIN_H)
    assert m.is_machine_bulk is False

    for subj in ("Your receipt from Anthropic, PBC #0000", "Your Account Statement is Now Available",
                 "An app-specific password was generated", "You made a $12.34 transaction"):
        assert Message(uid=3, subject=subj, headers=ANTHROPIC_LOGIN_H).is_machine_bulk is False, subj


def test_machine_bulk_needs_both_verp_and_esp():
    assert Message(uid=4, subject="Don't get locked out", headers=HOSTING_H).is_machine_bulk is False
    assert Message(uid=5, subject="hi", headers={"x-sg-eid": "a"}).is_machine_bulk is False
    assert Message(uid=6, from_addr="bob@foo.com", subject="hi").is_machine_bulk is False


def test_brief_html_escapes_message_text():
    """Subjects and sender names are attacker-controlled. They must not inject markup."""
    m = Message(uid=1, from_addr="x@y.com", from_name='<script>alert("x")</script>',
                subject='Sale <b>50% off</b> & "more" <img src=x onerror=alert(1)>',
                date=NOW, headers={})
    html = format_brief_html([(m, 10, "direct/personal")], now=NOW)
    assert "<script>" not in html
    assert "onerror" not in html or "&lt;img" in html
    assert "&lt;script&gt;" in html
    assert "&amp;" in html and "&quot;" in html or "&#x27;" in html or "&lt;b&gt;" in html
    assert "50% off" in html  # the readable text survives


def test_brief_html_renders_states():
    verp = {"return-path": "<bounces+1=example.com@em0.example.com>", "x-sg-eid": "a"}
    rows = [
        (Message(uid=1, from_addr="a@x.com", from_name="Bob", subject="Hi",
                 date=NOW, flags=(), headers={}), 130, "VIP sender, direct/personal, unread"),
        (Message(uid=2, from_addr="n@ads.com", from_name="Ads", subject="Sale",
                 date=NOW, flags=("\\Seen",), headers=verp), -5, "direct/personal"),
    ]
    html = format_brief_html(rows, top_n=1, now=NOW)
    assert 'class="chip vip"' in html and "VIP" in html
    assert 'class="chip unread"' in html and "Unread" in html
    assert "and 1 more" in html                  # top_n truncation notice
    assert "prefers-color-scheme: dark" in html  # dark mode survives
    assert "max-width:600px" in html             # email-safe width
    assert "http://" not in html.replace("http://www.w3.org", "")  # no external assets

    full = format_brief_html(rows, top_n=2, now=NOW)
    assert 'class="chip mktg"' in full and "Marketing" in full


def test_brief_html_empty_state():
    html = format_brief_html([], now=NOW)
    assert "Inbox is calm" in html
    assert "<b>0</b> items" in html


def test_machine_bulk_is_demoted_but_never_dropped():
    cfg = parse_config(_cfg_dict())
    marketing = Message(uid=1, from_addr="newsletter@shop.example.com", subject="Spring Sale",
                        date=NOW, headers=MARKETING_H)
    personal = Message(uid=2, from_addr="bob@foo.com", subject="question",
                       date=NOW, headers={})
    ranked = rank_inbox([marketing, personal], cfg, now=NOW)
    uids = [m.uid for m, _s, _r in ranked]
    assert uids == [2, 1], "marketing must rank below personal"
    assert len(ranked) == 2, "soft signal must never drop a message from the brief"


# ---- config ----
def _cfg_dict():
    return {
        "account": {"address": "me@me.com"},
        "scan": {"window_days": 7, "max_messages": 50, "exclude_bulk": True},
        "brief": {"hour": 8, "minute": 0, "folders": ["INBOX"]},
        "triage": {"rules": [
            {"match": "bob@*", "priority": "high"},
            {"match": "*@substack.com", "priority": "low"},
        ]},
        "cleanup": {"allow_delete": False, "rules": [
            {"match": "*newsletter*", "action": "move", "folder": "News"},
        ]},
    }


# ---- multi-account config ----

def test_legacy_single_account_still_works():
    """The existing [account] form must keep working unchanged."""
    accts = parse_accounts(_cfg_dict())
    assert accts.names == ["default"]
    a = accts.get()
    assert a.address == "me@me.com"
    assert a.keychain_service == "icloud-mcp"
    assert a.keychain_account == "me"          # derived from the address
    assert a.send_enabled is True
    assert a.window_days == 7                  # shared settings still apply


def test_multi_account_parses_and_isolates_state():
    d = {
        "accounts": {
            "main": {"address": "a@me.com", "default": True},
            "work": {"address": "b@icloud.com",
                        "keychain_service": "icloud-mcp-work",
                        "send_enabled": False},
        },
        "scan": {"window_days": 14},
    }
    accts = parse_accounts(d)
    assert sorted(accts.names) == ["main", "work"]
    assert accts.default_name == "main"

    p, s = accts.get("main"), accts.get("work")
    assert p.keychain_service == "icloud-mcp"                 # default service
    assert s.keychain_service == "icloud-mcp-work"         # explicit
    assert s.keychain_account == "b"
    assert p.window_days == 14 and s.window_days == 14        # shared settings inherited

    # Trusted stores must NOT be shared, or one account's approvals leak to another.
    assert p.trusted_store_path != s.trusted_store_path


def test_send_enabled_false_blocks_sending(tmp_path):
    """A no-send account's guardrail must live in code, not in anyone's memory."""
    d = {"accounts": {"ro": {"address": "b@icloud.com", "send_enabled": False}},
         "send": {"trusted_store": str(tmp_path / "t.json")}}
    cfg = parse_accounts(d).get("ro")
    assert cfg.send_enabled is False
    res = MailSender(cfg).send("anyone@x.com", "s", "b", confirm=True)
    assert res.sent is False
    assert "send" in res.detail.lower() and "disabled" in res.detail.lower()


def test_unknown_account_is_a_clear_error():
    accts = parse_accounts(_cfg_dict())
    with pytest.raises(ConfigError) as e:
        accts.get("nope")
    assert "nope" in str(e.value)


def test_config_ok():
    c = parse_config(_cfg_dict())
    assert c.imap_username == "me"
    assert c.window_days == 7 and c.exclude_bulk is True
    assert len(c.triage_rules) == 2 and len(c.cleanup_rules) == 1


def test_config_bad_address():
    with pytest.raises(ConfigError):
        parse_config({"account": {"address": "not-an-email"}})


def test_config_move_needs_folder():
    d = _cfg_dict()
    d["cleanup"]["rules"] = [{"match": "x", "action": "move"}]
    with pytest.raises(ConfigError):
        parse_config(d)


def test_config_bad_priority():
    d = _cfg_dict()
    d["triage"]["rules"] = [{"match": "x", "priority": "urgent"}]
    with pytest.raises(ConfigError):
        parse_config(d)


# ---- rules ----
def test_priority_high_wins():
    c = parse_config(_cfg_dict())
    bob = mk(1, frm="bob@foo.com")
    assert priority_for(bob, c.triage_rules) == "high"
    sub = mk(2, frm="digest@substack.com")
    assert priority_for(sub, c.triage_rules) == "low"
    rando = mk(3, frm="rando@nowhere.com")
    assert priority_for(rando, c.triage_rules) is None


def test_cleanup_subject_match():
    c = parse_config(_cfg_dict())
    m = mk(1, frm="x@y.com", subj="Weekly Newsletter roundup")
    r = cleanup_action_for(m, c.cleanup_rules)
    assert r is not None and r.action == "move" and r.folder == "News"


# ---- triage ----
def test_rank_excludes_bulk_and_orders_vip_first():
    c = parse_config(_cfg_dict())
    msgs = [
        mk(1, frm="rando@nowhere.com", subj="random", days_old=1),
        mk(2, frm="bob@foo.com", subj="call me", days_old=0),
        mk(3, frm="news@list.com", subj="promo", bulk=True),  # bulk -> excluded
    ]
    ranked = rank_inbox(msgs, c, now=NOW)
    uids = [m.uid for m, _, _ in ranked]
    assert 3 not in uids           # bulk excluded
    assert uids[0] == 2            # VIP Bob ranks first
    brief = format_brief(ranked)
    assert "Bob" in brief or "bob@foo.com" in brief


def test_brief_empty():
    assert "calm" in format_brief([]).lower()


# ---- unsubscribe ----
def test_unsub_one_click():
    m = mk(1, extra={
        "list-unsubscribe": "<https://x.com/u?tok=1>, <mailto:u@x.com>",
        "list-unsubscribe-post": "List-Unsubscribe=One-Click",
    })
    plan = parse_unsubscribe(m)
    assert plan.method == "one-click" and plan.target.startswith("https://")


def test_unsub_mailto_when_no_post():
    m = mk(1, extra={"list-unsubscribe": "<mailto:bye@x.com>"})
    plan = parse_unsubscribe(m)
    assert plan.method == "mailto" and plan.target == "bye@x.com"


def test_unsub_manual_when_https_only_no_post():
    m = mk(1, extra={"list-unsubscribe": "<https://x.com/u>"})
    plan = parse_unsubscribe(m)
    assert plan.method == "manual"


def test_unsub_none():
    assert parse_unsubscribe(mk(1)).method == "none"


# ---- calendar timezone: unset means the machine's local zone ----
def test_calendar_timezone_defaults_to_empty():
    """No zone is baked in: an unset [calendar].timezone stays empty in config."""
    assert parse_config(_cfg_dict()).calendar_timezone == ""


def test_empty_timezone_resolves_to_the_system_zone(monkeypatch):
    from zoneinfo import ZoneInfo
    from icloud_mcp import server
    from icloud_mcp.config import resolve_timezone, system_timezone
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    assert system_timezone() == ZoneInfo("Asia/Tokyo")
    assert resolve_timezone("") == ZoneInfo("Asia/Tokyo")
    assert resolve_timezone("   ") == ZoneInfo("Asia/Tokyo")
    cfg = parse_config(_cfg_dict())
    tz = server._local_tz(cfg)
    assert isinstance(tz, ZoneInfo) and tz.key == "Asia/Tokyo"   # named, so TZID works


def test_explicit_timezone_wins_and_a_typo_falls_back(monkeypatch):
    from zoneinfo import ZoneInfo
    from icloud_mcp.config import resolve_timezone
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    assert resolve_timezone("Europe/Paris") == ZoneInfo("Europe/Paris")
    assert resolve_timezone("Mars/Olympus") == ZoneInfo("Asia/Tokyo")


def test_system_timezone_without_tz_env_is_a_named_zone(monkeypatch):
    """Falls back through /etc/localtime to UTC; never a bare fixed offset."""
    from zoneinfo import ZoneInfo
    from icloud_mcp.config import system_timezone
    monkeypatch.delenv("TZ", raising=False)
    tz = system_timezone()
    assert isinstance(tz, ZoneInfo) and tz.key
