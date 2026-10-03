"""The opt-in remote WRITE profile.

The read profile stays the default and is covered by test_remote_profile.py.
These tests pin the rules the write profile enforces IN CODE, because over the
phone the model deciding to call a tool is reading attacker-controlled email:

- never-reachable tools stay absent even in the write profile;
- remote send/reply cannot express attachments (they would read files off the Mac);
- recipients in Contacts are auto-approved, anyone else still needs confirm=True;
- daily caps refuse BEFORE acting;
- Notes stay blocked for move/trash/reply;
- events with attendees cannot be edited remotely (iCloud would email them).

No network: every server call is replaced with a fake.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from icloud_mcp import remote, server, transport


def _names(srv) -> set[str]:
    return {t.name for t in asyncio.run(srv.list_tools())}


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "CAPS_PATH", str(tmp_path / "caps.json"))
    remote.set_caps(None)
    remote.set_blocked_folders(remote.DEFAULT_BLOCKED_FOLDERS)
    log = []
    monkeypatch.setattr(server, "_audit", lambda a, d: log.append((a, d)))
    return log


# ---------------------------------------------------------------- surface
def test_default_profile_is_still_read_only():
    names = _names(remote.build_server())
    for w in remote.REMOTE_WRITE_TOOLS:
        assert w not in names


def test_write_profile_adds_exactly_the_write_tools():
    read, write = _names(remote.build_server()), _names(remote.build_server(profile="write"))
    assert write - read == set(remote.REMOTE_WRITE_TOOLS)


@pytest.mark.parametrize("name", remote.EXCLUDED_TOOLS)
def test_never_reachable_even_in_write_profile(name):
    assert name not in _names(remote.build_server(profile="write"))


def test_unknown_profile_refuses_to_start():
    with pytest.raises(ValueError):
        remote.build_server(profile="admin")


def test_config_profile_typo_refuses_to_start():
    block = {"team_domain": "yourteam.cloudflareaccess.com", "aud": "x", "allowed_emails": ["a@b.c"],
             "public_hostname": "h.example.com", "profile": "wirte"}
    with pytest.raises(ValueError):
        transport.config_from_block(block)


def test_config_defaults_to_read():
    block = {"team_domain": "yourteam.cloudflareaccess.com", "aud": "x", "allowed_emails": ["a@b.c"],
             "public_hostname": "h.example.com"}
    _cfg, opts = transport.config_from_block(block)
    assert opts["profile"] == "read"


@pytest.mark.parametrize("fn", [remote.r_send_mail, remote.r_reply_mail])
def test_remote_send_cannot_express_attachments(fn):
    assert "attachments" not in inspect.signature(fn).parameters
    assert "attachments" in inspect.signature(server.send_mail).parameters


# ---------------------------------------------------------------- send policy
class _Trusted:
    def __init__(self, addrs): self.s = {a.lower() for a in addrs}
    def is_trusted(self, a): return a.lower() in self.s


class _Sender:
    def __init__(self, trusted): self.trusted = _Trusted(trusted)


@pytest.fixture
def send_env(monkeypatch):
    calls = []

    state = {"trusted": ["old@friend.example.com"], "contacts": {"jane@contact.example.com"}}

    def fake_send(**kw):
        # Mirrors MailSender.send: trusted-only sends need no confirm.
        calls.append(kw)
        everyone = remote._addrs(kw["to"], kw.get("cc"))
        if kw["confirm"] or all(a in state["trusted"] for a in everyone):
            return {"sent": True, "needs_confirmation": False, "detail": "sent"}
        return {"sent": False, "needs_confirmation": True, "detail": "new recipient"}

    monkeypatch.setattr(server, "send_mail", fake_send)
    monkeypatch.setattr(server, "_sender", lambda account=None: _Sender(state["trusted"]))
    monkeypatch.setattr(remote, "_contact_addresses", lambda: set(state["contacts"]))
    return calls, state


def test_trusted_recipient_sends_without_confirm(send_env):
    calls, _ = send_env
    out = remote.r_send_mail("old@friend.example.com", "s", "b")
    assert out["sent"] and calls[-1]["confirm"] is False


def test_contact_is_auto_approved(send_env):
    calls, _ = send_env
    out = remote.r_send_mail("Jane <jane@contact.example.com>", "s", "b")
    assert out["sent"] and calls[-1]["confirm"] is True


def test_stranger_needs_confirm(send_env):
    calls, _ = send_env
    out = remote.r_send_mail("evil@attacker.example.com", "s", "b")
    assert not out["sent"] and out["needs_confirmation"]
    assert calls[-1]["confirm"] is False


def test_contact_in_to_cannot_smuggle_stranger_in_cc(send_env):
    calls, _ = send_env
    out = remote.r_send_mail("jane@contact.example.com", "s", "b", cc=["evil@attacker.example.com"])
    assert not out["sent"] and calls[-1]["confirm"] is False


def test_stranger_with_confirm_sends_and_counts(send_env, _isolate):
    out = remote.r_send_mail("new@person.example.com", "s", "b", confirm=True)
    assert out["sent"]
    assert remote._load_counts()["new_recipient_sends"] == 1


def test_attachments_never_forwarded(send_env):
    calls, _ = send_env
    remote.r_send_mail("old@friend.example.com", "s", "b")
    assert calls[-1]["attachments"] is None


# ---------------------------------------------------------------- caps
def test_send_cap_refuses_before_sending(send_env):
    calls, _ = send_env
    remote.set_caps({"sends": 2})
    remote.r_send_mail("old@friend.example.com", "s", "b")
    remote.r_send_mail("old@friend.example.com", "s", "b")
    with pytest.raises(ToolError, match="daily phone limit"):
        remote.r_send_mail("old@friend.example.com", "s", "b")
    assert len(calls) == 2


def test_new_recipient_cap(send_env):
    remote.set_caps({"new_recipient_sends": 1})
    remote.r_send_mail("a@new.example.com", "s", "b", confirm=True)
    with pytest.raises(ToolError, match="new_recipient_sends"):
        remote.r_send_mail("b@new.example.com", "s", "b", confirm=True)


def test_needs_confirmation_does_not_consume_cap(send_env):
    remote.set_caps({"sends": 1})
    remote.r_send_mail("evil@attacker.example.com", "s", "b")      # refused, not sent
    remote.r_send_mail("old@friend.example.com", "s", "b")          # still allowed
    assert remote._load_counts()["sends"] == 1


def test_trash_cap_counts_messages_not_calls(monkeypatch):
    monkeypatch.setattr(server, "trash", lambda **kw: {"ok": True, "trashed": len(kw["uids"])})
    remote.set_caps({"trashed": 5})
    remote.r_trash([1, 2, 3])
    with pytest.raises(ToolError, match="trashed"):
        remote.r_trash([4, 5, 6])


def test_counts_reset_on_a_new_day(monkeypatch, send_env):
    remote.set_caps({"sends": 1})
    remote.r_send_mail("old@friend.example.com", "s", "b")
    monkeypatch.setattr(remote, "_today", lambda: "2099-01-01")
    remote.r_send_mail("old@friend.example.com", "s", "b")


# ---------------------------------------------------------------- folders + calendar
@pytest.mark.parametrize("dest", ["Notes", "Notes/Taxes", "notes"])
def test_move_into_notes_refused(monkeypatch, dest):
    monkeypatch.setattr(server, "move_message", lambda **kw: pytest.fail("reached server"))
    with pytest.raises(ToolError):
        remote.r_move_message(1, dest)


def test_trash_from_notes_refused(monkeypatch):
    monkeypatch.setattr(server, "trash", lambda **kw: pytest.fail("reached server"))
    with pytest.raises(ToolError):
        remote.r_trash([1], folder="Notes")


class _Ev:
    summary, href = "Dinner", "/cal/x.ics"


class _Cal:
    def __init__(self, raw): self.raw = raw
    def find_by_uid(self, uid): return _Ev()
    def get_raw(self, href): return True, self.raw


_PLAIN = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nSUMMARY:Dinner\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
_WITH_ATT = ("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nSUMMARY:Dinner\r\n"
             "ATTENDEE;CN=Jane:mailto:jane@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")


def test_update_event_refuses_attendee_events(monkeypatch):
    monkeypatch.setattr(server, "_one", lambda *a, **k: object())
    monkeypatch.setattr(server, "_caldav", lambda cfg: _Cal(_WITH_ATT))
    monkeypatch.setattr(server, "update_event", lambda **kw: pytest.fail("reached server"))
    with pytest.raises(ToolError, match="attendees"):
        remote.r_update_event("x", summary="New", confirm=True)


def test_update_event_allows_plain_events(monkeypatch):
    monkeypatch.setattr(server, "_one", lambda *a, **k: object())
    monkeypatch.setattr(server, "_caldav", lambda cfg: _Cal(_PLAIN))
    monkeypatch.setattr(server, "update_event", lambda **kw: {"updated": True, "changed": ["SUMMARY"]})
    assert remote.r_update_event("x", summary="New", confirm=True)["updated"]


def test_every_write_is_audited(monkeypatch, _isolate):
    monkeypatch.setattr(server, "mark_read", lambda **kw: {"ok": True})
    remote.r_mark_read(7)
    assert any(a == "remote_write" and "kind=mark_read" in d for a, d in _isolate)


# ---------------------------------------------------------------- 8am brief
def test_brief_surfaces_phone_writes(tmp_path):
    from datetime import datetime, timezone
    from icloud_mcp import auditsum
    now = datetime(2026, 10, 3, 14, 0, tzinfo=timezone.utc)
    log = tmp_path / "audit.log"
    log.write_text(
        "2026-10-03T08:00:00+00:00\tremote_write\tkind=send to=a@b.c cc=[] sent=True contacts_auto=[] new=[]\n"
        "2026-10-03T08:01:00+00:00\tremote_write\tkind=send to=x@y.z cc=[] sent=False contacts_auto=[] new=['x@y.z']\n"
        "2026-10-03T08:02:00+00:00\tremote_write\tkind=trash INBOX n=3\n"
        "2026-10-03T08:03:00+00:00\tremote_cap\tsends used=25 adding=1 cap=25\n")
    s = auditsum.summarize(str(log), now=now)
    assert s.remote_writes == {"send": 1, "trash": 1}
    line = auditsum.format_line(s)
    assert "phone writes: send 1, trash 1" in line
    assert "1 email(s) sent from the phone" in line
    assert "stopped by a daily cap" in line
