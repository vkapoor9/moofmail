"""Regression tests for five safety gaps found in a review before open-sourcing.

Each one was a place where the code did less than the documentation promised.
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path

from icloud_mcp import server
from icloud_mcp.config import parse_config
from icloud_mcp.models import Message
from icloud_mcp.smtp_send import MailSender, SendResult


def _cfg(tmp_path, **extra):
    data = {"account": {"address": "you@icloud.com", "send_enabled": True,
                        "trusted_store": str(tmp_path / "t.json"), **extra},
            "cleanup": {"allow_delete": True,
                        "rules": [{"match": "*@junk.example.com", "action": "delete"},
                                  {"match": "*@notes.example.com", "action": "move",
                                   "folder": "Notes/Journal"}]}}
    return parse_config(data)


# 1. `python -m icloud_mcp.server` must see every tool ------------------------
def test_main_guard_is_the_last_statement():
    """Anything defined after `if __name__ == "__main__": main()` never registers
    when the module runs as a script. Four cleanup tools once went missing so."""
    tree = ast.parse(Path(server.__file__).read_text())
    last = tree.body[-1]
    assert isinstance(last, ast.If) and "__name__" in ast.unparse(last.test)


# 2. mailto unsubscribe goes through the send gate ----------------------------
class _FakeReader:
    def __init__(self, msg=None):
        self.msg, self.trashed, self.moved, self.deleted = msg, [], [], []
    def get_message(self, uid, folder="INBOX"):
        return self.msg
    def list_inbox(self, since_days=None):
        return self.msg
    def trash(self, uids, folder="INBOX"):
        self.trashed += list(uids)
        return len(uids), "Deleted Messages"
    def move_message(self, uid, dest, folder="INBOX"):
        self.moved.append((uid, dest))
    def delete_message(self, uid, folder="INBOX"):
        self.deleted.append(uid)
    def archive(self, uid):
        pass
    def mark_read(self, uid):
        pass


class _FakeSender:
    def __init__(self):
        self.calls = []
    def send(self, to, subject, body, confirm=False, **kw):
        self.calls.append({"to": to, "confirm": confirm})
        return SendResult(False, True, "new recipient")


def _mailto_msg():
    m = Message(uid=7, from_addr="news@list.example.com", from_name="", subject="hi",
                date=datetime.now(timezone.utc))
    m.headers = {"list-unsubscribe": "<mailto:leave@list.example.com>"}
    return m


def test_mailto_unsubscribe_does_not_self_confirm(monkeypatch):
    sender, used = _FakeSender(), []
    monkeypatch.setattr(server, "_reader", lambda account=None: _FakeReader(_mailto_msg()))
    monkeypatch.setattr(server, "_sender", lambda account=None: used.append(account) or sender)
    monkeypatch.setattr(server, "_audit", lambda *a: None)
    monkeypatch.setattr(server, "parse_unsubscribe",
                        lambda m: type("P", (), {"method": "mailto",
                                                 "target": "leave@list.example.com",
                                                 "reason": ""})())
    out = server.do_unsubscribe(7, account="work")
    assert sender.calls[0]["confirm"] is False      # never approves itself
    assert used == ["work"]                          # sends from the account asked for
    assert out["ok"] is False and out["needs_confirmation"] is True


# 3. apply_rules: right account, Trash not purge, never into Notes ------------
def test_apply_rules_trashes_instead_of_purging(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path)
    msgs = [Message(uid=1, from_addr="a@junk.example.com", from_name="", subject="x",
                    date=datetime.now(timezone.utc)),
            Message(uid=2, from_addr="b@notes.example.com", from_name="", subject="y",
                    date=datetime.now(timezone.utc))]
    reader, asked = _FakeReader(msgs), []
    monkeypatch.setattr(server, "_cfg", lambda account=None, service=None: cfg)
    monkeypatch.setattr(server, "_reader", lambda account=None: asked.append(account) or reader)
    monkeypatch.setattr(server, "_audit", lambda *a: None)
    out = server.apply_rules(dry_run=False, account="work")
    assert set(asked) == {"work"}                    # plan and action on one account
    assert reader.trashed == [1] and reader.deleted == []
    assert reader.moved == []                        # Notes destination refused
    refused = [e for e in out["executed"] if e["uid"] == 2]
    assert refused and "blocked" in refused[0]["result"]


# 4. invitations respect the send switch --------------------------------------
def test_attendees_refused_when_sending_is_off(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path, send_enabled=False)
    monkeypatch.setattr(server, "_one", lambda account=None, service=None: cfg)
    monkeypatch.setattr(server, "_caldav",
                        lambda c: (_ for _ in ()).throw(AssertionError("no CalDAV call")))
    out = server.create_event("Lunch", "2026-01-15T12:00", "2026-01-15T13:00",
                              attendees=["friend@example.com"], confirm=True)
    assert out["created"] is False and "turned off" in out["detail"]


# 5. attachments always need an explicit confirm ------------------------------
def test_attachment_to_trusted_recipient_still_needs_confirm(tmp_path):
    sender = MailSender(_cfg(tmp_path))
    sender.trusted.add("known@example.com")
    f = tmp_path / "private.txt"
    f.write_text("secret")
    res = sender.send("known@example.com", "s", "b", attachments=[str(f)])
    assert res.sent is False and res.needs_confirmation is True
    assert "private.txt" in res.detail


# 6. no code path can purge mail ---------------------------------------------
def test_no_unscoped_expunge_anywhere():
    """A bare EXPUNGE purges every \\Deleted message in the folder, including ones
    another client flagged. Only the UID-scoped form may exist."""
    import icloud_mcp
    for f in Path(icloud_mcp.__file__).parent.glob("*.py"):
        assert "expunge()" not in f.read_text(), f.name
        assert "delete_messages(" not in f.read_text(), f.name
