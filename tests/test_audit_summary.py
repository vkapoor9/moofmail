"""The audit log summarized into the morning brief.

Calibrated against cases whose answer is known in advance, including known
NEGATIVES: an old refusal, a dry-run cleanup and an unconfirmed send must not
register. A detector that has only seen positives has not been tested.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from icloud_mcp import server, smtp_send
from icloud_mcp.auditsum import AuditSummary, format_line, summarize
from icloud_mcp.config import parse_config
from icloud_mcp.smtp_send import MailSender
from icloud_mcp.triage import format_brief, format_brief_html

NOW = datetime(2026, 9, 23, 14, 0, tzinfo=timezone.utc)


def _log(tmp_path, rows):
    p = tmp_path / "audit.log"
    p.write_text("".join(f"{(NOW - timedelta(hours=h)).isoformat()}\t{a}\t{d}\n"
                         for h, a, d in rows))
    return str(p)


def test_quiet_day_counts_and_raises_no_alert(tmp_path):
    p = _log(tmp_path, [
        (50, "remote_request", "me@x.com /mcp"),     # known from before the window
        (1, "remote_request", "me@x.com /mcp"),
        (2, "remote_request", "me@x.com /mcp"),
        (3, "send_mail", "to=a@x.com cc=[] sent=True confirm=False attachments=0 trusted_new=[]"),
        (4, "search_mail", "q='x' n=3"),
    ])
    s = summarize(p, now=NOW)
    assert (s.sends, s.remote_calls, s.alerts) == (1, 2, [])
    assert format_line(s) == ("Last 24h: 1 send (0 to new recipients) | "
                              "2 remote calls | nothing refused")


def test_events_older_than_the_window_are_ignored(tmp_path):
    """Known negative: last week's refusals must not alarm this morning."""
    p = _log(tmp_path, [
        (30, "remote_denied", "/mcp token rejected"),
        (48, "blocked_folder", "get_message folder='Notes'"),
        (25, "send_mail", "to=n@x.com sent=True trusted_new=['n@x.com']"),
    ])
    s = summarize(p, now=NOW)
    assert s.alerts == [] and s.sends == 0


def test_new_recipient_is_an_alert(tmp_path):
    p = _log(tmp_path, [
        (1, "send_mail", "to=new@x.com cc=[] sent=True confirm=True attachments=0 "
                         "trusted_new=['new@x.com']"),
    ])
    s = summarize(p, now=NOW)
    assert s.new_recipients == ["new@x.com"]
    assert "new recipient trusted: new@x.com" in format_line(s)


def test_unconfirmed_send_is_not_a_send(tmp_path):
    """Known negative: needs_confirmation logs sent=False and delivered nothing."""
    p = _log(tmp_path, [(1, "send_mail", "to=a@x.com sent=False confirm=False trusted_new=[]")])
    assert summarize(p, now=NOW).sends == 0


def test_refusals_blocked_notes_reset_and_new_identity_all_alert(tmp_path):
    p = _log(tmp_path, [
        (30, "remote_request", "me@x.com /mcp"),
        (1, "remote_denied", "/mcp token rejected"),
        (1, "blocked_folder", "get_message folder='Notes'"),
        (1, "reset_trusted_recipients", "cleared"),
        (2, "remote_request", "me@x.com /mcp"),
        (2, "remote_request", "someone@else.com /mcp"),
    ])
    alerts = summarize(p, now=NOW).alerts
    assert len(alerts) == 4
    assert any("someone@else.com" in a for a in alerts)


def test_previews_and_empty_trash_are_not_deletions(tmp_path):
    """Known negatives: dry runs and zero-message moves destroy nothing."""
    p = _log(tmp_path, [
        (1, "bulk_trash", "senders=3 confirm=False trashed=0"),
        (1, "trash", "INBOX n=0 -> Deleted Messages"),
        (1, "delete_event", "UID 'x' recurring=False ok=False"),
        (1, "trash", "INBOX n=4 -> Deleted Messages"),
        (1, "delete_event", "UID 'y' recurring=False ok=True"),
        (1, "bulk_trash", "senders=3 confirm=True trashed=12"),
    ])
    assert summarize(p, now=NOW).deletions == 3


def test_missing_log_is_reported_as_unknown_never_as_quiet(tmp_path):
    s = summarize(str(tmp_path / "absent.log"), now=NOW)
    assert s.ok is False
    line = format_line(s)
    assert "could NOT be read" in line and "nothing refused" not in line


def test_garbage_lines_do_not_crash_the_brief(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text("not a log line\nbad-ts\tsend_mail\tsent=True\n")
    s = summarize(str(p), now=NOW)
    assert s.ok and s.malformed == 2 and s.sends == 0


def test_brief_puts_alerts_at_the_top_and_quiet_line_at_the_bottom():
    quiet = AuditSummary(sends=1, remote_calls=3)
    loud = AuditSummary(remote_denied=2)
    html_q = format_brief_html([], audit=quiet)
    html_l = format_brief_html([], audit=loud)
    assert html_q.index('class="audit"') > html_q.index('class="calm"')
    assert html_l.index('class="audit alert"') < html_l.index('class="calm"')
    assert "2 remote request(s) refused" in html_l
    assert format_brief([], audit=loud).startswith("Last 24h:")


def test_brief_escapes_addresses_in_the_audit_block():
    s = AuditSummary(new_recipients=["<script>@x.com"])
    assert "<script>" not in format_brief_html([], audit=s)


def test_brief_without_audit_is_unchanged():
    assert 'class="audit' not in format_brief_html([])


def test_blocked_notes_read_is_written_to_the_audit_log(tmp_path):
    with pytest.raises(ToolError):
        server.get_message(1, folder="Notes/Recipes")
    text = open(server._AUDIT).read()
    assert "\tblocked_folder\tget_message folder='Notes/Recipes'" in text


class _FakeSMTP:
    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def ehlo(self): pass
    def starttls(self, **k): pass
    def login(self, *a): pass
    def send_message(self, msg): return {}


def test_send_reports_which_recipients_it_newly_trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(smtp_send.smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setattr(smtp_send, "get_password", lambda *a: "pw")
    monkeypatch.setattr(smtp_send, "append_to_sent", lambda *a: (True, "Sent Messages"))
    cfg = parse_config({"account": {"address": "me@me.com"},
                        "send": {"trusted_store": str(tmp_path / "t.json")}})
    s = MailSender(cfg)
    s.trusted.add("known@x.com")
    res = s.send("known@x.com", "s", "b", cc=["new@x.com"], confirm=True)
    assert res.sent is True
    assert res.newly_trusted == ["new@x.com"]          # known@ was already trusted
    again = s.send("known@x.com", "s", "b", cc=["new@x.com"], confirm=True)
    assert again.newly_trusted == []                    # second send grants nothing


def test_identity_is_case_and_whitespace_insensitive(tmp_path):
    """An upper-cased or space-padded claim must not count as an extra person."""
    p = _log(tmp_path, [
        (50, "remote_request", "me@x.com /mcp"),
        (1, "remote_request", "me@x.com /mcp"),
        (1, "remote_request", "ME@X.COM /mcp"),
        (1, "remote_request", " me@x.com  /mcp"),
    ])
    s = summarize(p, now=NOW)
    assert s.remote_identities == ["me@x.com"] and s.alerts == []


def test_owner_with_two_known_identities_is_not_an_alert(tmp_path):
    """Known negative: two sign-in methods can give one owner two emails."""
    p = _log(tmp_path, [
        (40, "remote_request", "me@example.org /mcp"),
        (41, "remote_request", "me@example.com /mcp"),
        (1, "remote_request", "me@example.org /mcp"),
        (2, "remote_request", "ME@example.com /mcp"),
    ])
    s = summarize(p, now=NOW)
    assert len(s.remote_identities) == 2 and s.alerts == []


def test_an_identity_never_seen_before_is_an_alert(tmp_path):
    p = _log(tmp_path, [
        (40, "remote_request", "me@x.com /mcp"),
        (1, "remote_request", "stranger@y.com /mcp"),
    ])
    assert summarize(p, now=NOW).alerts == ["first-ever remote login by: stranger@y.com"]


def test_remote_layer_notes_refusal_is_logged_too():
    """A remote layer that refuses first must still log the refusal."""
    # A remote transport is not part of every distribution of this package.
    remote = pytest.importorskip("icloud_mcp.remote")
    with pytest.raises(ToolError):
        remote.list_inbox(folder="Notes")
    assert "\tblocked_folder\tremote folder='Notes'" in open(server._AUDIT).read()
