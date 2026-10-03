"""Tests for TrustedStore (learn-on-approve) and cleanup planning — no network."""
from __future__ import annotations

from datetime import datetime, timezone

from icloud_mcp.config import parse_config
from icloud_mcp.models import Message, parse_from
from icloud_mcp.rules import plan_cleanup
from icloud_mcp.imap_read import find_sent_folder
from icloud_mcp.scrub import check_outbound, autofix
from icloud_mcp.smtp_send import TrustedStore, MailSender, reply_recipients, clean_header


def mk(uid, frm, subj=""):
    n, a = parse_from(frm)
    return Message(uid=uid, from_addr=a, from_name=n, subject=subj,
                   date=datetime.now(timezone.utc))


def test_trusted_store_roundtrip(tmp_path):
    p = tmp_path / "trusted.json"
    ts = TrustedStore(p)
    assert not ts.is_trusted("a@b.com")
    ts.add("A@B.com")
    assert ts.is_trusted("a@b.com")          # case-insensitive
    assert TrustedStore(p).is_trusted("a@b.com")  # persisted across instances
    ts.clear()
    assert not TrustedStore(p).is_trusted("a@b.com")


class _FakeClient:
    """Stands in for IMAPClient. list_folders() -> (flags, delimiter, name)."""
    def __init__(self, folders):
        self.folders = folders
    def list_folders(self):
        return self.folders


def test_find_sent_folder_prefers_special_use_flag():
    c = _FakeClient([
        ((rb"\HasNoChildren",), b"/", "Sent Items"),        # decoy, no \Sent flag
        ((rb"\HasNoChildren", rb"\Sent"), b"/", "Sent Messages"),
        ((rb"\HasNoChildren",), b"/", "INBOX"),
    ])
    assert find_sent_folder(c) == "Sent Messages"


def test_find_sent_folder_falls_back_by_name():
    """No SPECIAL-USE flag: prefer 'Sent Messages' over the empty 'Sent Items' decoy."""
    c = _FakeClient([
        ((rb"\HasNoChildren",), b"/", "Sent Items"),
        ((rb"\HasNoChildren",), b"/", "Sent Messages"),
        ((rb"\HasNoChildren",), b"/", "INBOX"),
    ])
    assert find_sent_folder(c) == "Sent Messages"

    only_items = _FakeClient([((rb"\HasNoChildren",), b"/", "Sent Items")])
    assert find_sent_folder(only_items) == "Sent Items"


def test_find_sent_folder_survives_a_broken_server():
    class Broken:
        def list_folders(self):
            raise RuntimeError("NO server said no")
    assert find_sent_folder(Broken()) == "Sent Messages"   # safe default, never raises


def test_reply_recipients_keeps_others_and_drops_self():
    """Reply-all: To = original sender, Cc = everyone else except me and the sender."""
    me = "me@me.com"
    to_hdr = "Pat Example <me@me.com>, Alice <alice@example.com>"
    cc = reply_recipients(sender="carol@x.com", to_header=to_hdr, cc_header="", me=me)
    assert cc == ["alice@example.com"]      # self removed, sender not duplicated

    cc2 = reply_recipients(sender="carol@x.com",
                           to_header="me@me.com",
                           cc_header="Bob <bob@x.com>, carol@x.com", me=me)
    assert cc2 == ["bob@x.com"]             # sender de-duped out of Cc

    assert reply_recipients(sender="a@x.com", to_header="me@me.com",
                            cc_header="", me=me) == []


def test_scrub_blocks_em_dash_and_reports_soft_tells():
    r = check_outbound("Update — Monday", "Feel free to reach out. It’s fine.")
    assert r["ok"] is False
    chars = {h["char"] for h in r["hard"]}
    assert "—" in chars and "’" in chars   # em dash + curly apostrophe
    assert "feel free to" in r["soft"]

    clean = check_outbound("Update: Monday", "Reach out any time. It's fine.")
    assert clean["ok"] is True and clean["hard"] == []


def test_scrub_autofix_leaves_dashes_alone():
    """Quotes/ellipsis have exact equivalents. Dashes need a rewrite, so never guess."""
    assert autofix("“hi” ‘there’…") == '"hi" \'there\'...'
    assert "—" in autofix("keep — this")


def test_send_blocks_banned_characters(tmp_path):
    cfg = parse_config({"account": {"address": "me@me.com"},
                        "send": {"trusted_store": str(tmp_path / "t.json")}})
    s = MailSender(cfg)
    s.trusted.add("known@x.com")
    res = s.send("known@x.com", "Hi", "This — that")
    assert res.sent is False and res.needs_confirmation is False
    assert "em dash" in res.detail

    # Override exists for quoted replies that legitimately carry them. Prove it gets
    # PAST the style gate by failing on the next check instead (no network involved).
    res2 = s.send("not-an-address", "Hi", "This — that", allow_style=True)
    assert res2.sent is False and "invalid recipient" in res2.detail


def test_style_gate_can_be_disabled_in_config(tmp_path):
    """Default on for config.toml installs, but a fresh install must be able to
    turn it off so a new user's first reply is not refused over an em dash."""
    base = {"account": {"address": "me@me.com"},
            "send": {"trusted_store": str(tmp_path / "t.json")}}
    on = parse_config(base)
    assert on.style_gate is True

    off = parse_config({**base, "send": {**base["send"], "style_gate": False}})
    assert off.style_gate is False
    s = MailSender(off)
    s.trusted.add("known@x.com")
    res = s.send("not-an-address", "Hi", "This — that")   # em dash, gate disabled
    assert "style" not in res.detail.lower()               # got past the gate
    assert "invalid recipient" in res.detail


def test_clean_header_unfolds_wire_folding():
    """IMAP returns long headers with their folding intact. EmailMessage refuses to set a
    header containing CR/LF, so a reply into a long thread blew up before this."""
    folded = ("<a@mail.gmail.com>\r\n <b@example.com>\r\n\t<c@example.com>")
    out = clean_header(folded)
    assert "\r" not in out and "\n" not in out
    assert out == "<a@mail.gmail.com> <b@example.com> <c@example.com>"
    assert clean_header(None) == ""
    assert clean_header("  simple  ") == "simple"


def test_send_rejects_missing_attachment_before_touching_the_network(tmp_path):
    cfg = parse_config({"account": {"address": "me@me.com"},
                        "send": {"trusted_store": str(tmp_path / "t.json")}})
    s = MailSender(cfg)
    s.trusted.add("known@x.com")
    res = s.send("known@x.com", "s", "b", attachments=[str(tmp_path / "nope.md")])
    assert res.sent is False and res.needs_confirmation is False
    assert "attachment not found" in res.detail


def test_send_gate_checks_every_recipient(tmp_path):
    """A trusted To must not smuggle an untrusted Cc past the gate."""
    cfg = parse_config({"account": {"address": "me@me.com"},
                        "send": {"trusted_store": str(tmp_path / "t.json")}})
    s = MailSender(cfg)
    s.trusted.add("known@x.com")

    res = s.send("known@x.com", "s", "b", cc=["stranger@x.com"])
    assert res.sent is False and res.needs_confirmation is True
    assert "stranger@x.com" in res.detail
    assert not s.trusted.is_trusted("stranger@x.com")  # nothing trusted on refusal


def _cfg(allow_delete=False):
    return parse_config({
        "account": {"address": "me@me.com"},
        "cleanup": {"allow_delete": allow_delete, "rules": [
            {"match": "*newsletter*", "action": "move", "folder": "News"},
            {"match": "spam@*", "action": "delete"},
        ]},
    })


def test_plan_cleanup_move_and_delete_disabled():
    cfg = _cfg(allow_delete=False)
    msgs = [
        mk(1, "x@y.com", "Weekly Newsletter"),
        mk(2, "spam@bad.com", "junk"),
        mk(3, "friend@ok.com", "hello"),  # no rule -> not in plan
    ]
    plan = plan_cleanup(msgs, cfg.cleanup_rules, cfg.allow_delete)
    by_uid = {p["uid"]: p for p in plan}
    assert set(by_uid) == {1, 2}
    assert by_uid[1]["action"] == "move" and by_uid[1]["folder"] == "News"
    assert by_uid[2]["action"] == "skip"  # delete disabled
    assert "disabled" in by_uid[2]["note"]


def test_plan_cleanup_delete_enabled():
    cfg = _cfg(allow_delete=True)
    plan = plan_cleanup([mk(2, "spam@bad.com", "junk")], cfg.cleanup_rules, cfg.allow_delete)
    assert plan[0]["action"] == "delete"


def test_send_gate_splits_a_multi_address_to(tmp_path):
    """A comma-separated To is gated address by address, never as one blob.

    Before this, `to_norm` was the ENTIRE string, so a To carrying an untrusted
    address only tripped the gate because the composite matched nothing in the
    store. Worse, confirm=True then wrote that composite in as if it were an
    address, so the per-recipient check silently stopped meaning anything.
    """
    cfg = parse_config({"account": {"address": "me@me.com"},
                        "send": {"trusted_store": str(tmp_path / "t.json")}})
    s = MailSender(cfg)
    s.trusted.add("known@x.com")

    res = s.send("known@x.com, stranger@x.com", "s", "b")
    assert res.sent is False and res.needs_confirmation is True
    # Names the ONE genuinely new address, in the singular, not the whole string.
    assert "'stranger@x.com' is a new recipient" in res.detail
    assert not s.trusted.is_trusted("known@x.com, stranger@x.com")


def test_send_lets_a_fully_trusted_multi_address_to_through_the_gate(tmp_path):
    """Every address already trusted means no confirm, even with several in To.

    Proven by failing on the NEXT check (a missing attachment) rather than by
    reaching the network.
    """
    cfg = parse_config({"account": {"address": "me@me.com"},
                        "send": {"trusted_store": str(tmp_path / "t.json")}})
    s = MailSender(cfg)
    s.trusted.add("a@x.com")
    s.trusted.add("b@x.com")

    res = s.send("a@x.com, b@x.com", "s", "b",
                 attachments=[str(tmp_path / "nope.md")])
    assert res.needs_confirmation is False
    assert "attachment not found" in res.detail


def test_send_still_rejects_a_to_with_no_usable_address(tmp_path):
    cfg = parse_config({"account": {"address": "me@me.com"},
                        "send": {"trusted_store": str(tmp_path / "t.json")}})
    s = MailSender(cfg)
    for bad in ("", "   ", "not-an-address", "a@x.com, garbage"):
        res = s.send(bad, "s", "b")
        assert res.sent is False, bad
        assert "invalid recipient" in res.detail, bad


def test_send_mail_tool_exposes_cc():
    """The library supported cc all along; the MCP tool did not expose it, which
    is why a three-party thread had to be crammed into `to`."""
    import inspect
    from icloud_mcp import server
    assert "cc" in inspect.signature(server.send_mail).parameters
