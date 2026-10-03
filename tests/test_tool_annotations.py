"""Every tool must say whether it changes anything.

Claude clients use these hints to decide when to ask before a call, and the
Claude directory refuses tools without a title and a read-only or destructive
hint.
"""
import asyncio

from icloud_mcp import server

# Tools that change nothing on the account.
READ_ONLY = {
    "status", "list_inbox", "search_mail", "get_message", "list_folders",
    "triage_inbox", "morning_brief", "draft_reply", "find_unsubscribe",
    "sender_census", "cleanup_preview", "list_calendars", "list_events",
    "agenda", "free_slots", "search_contacts", "lookup_contact_email",
    "list_contact_groups",
}
# Tools whose effect cannot be quietly undone: outbound mail, deletions,
# overwrites, and anything that widens what may be sent.
DESTRUCTIVE = {
    "send_mail", "reply_mail", "do_unsubscribe", "trash", "bulk_trash",
    "apply_rules", "update_event", "delete_event", "reset_trusted_recipients",
}


def _tools():
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_every_tool_has_title_and_hints():
    for name, t in _tools().items():
        a = t.annotations
        assert t.title, f"{name} has no title"
        assert a is not None, f"{name} has no annotations"
        assert a.readOnlyHint is not None and a.destructiveHint is not None, name


def test_read_only_set_is_exact():
    got = {n for n, t in _tools().items() if t.annotations.readOnlyHint}
    assert got == READ_ONLY


def test_destructive_set_is_exact():
    got = {n for n, t in _tools().items() if t.annotations.destructiveHint}
    assert got == DESTRUCTIVE


def test_no_tool_is_both_read_only_and_destructive():
    for n, t in _tools().items():
        assert not (t.annotations.readOnlyHint and t.annotations.destructiveHint), n


def test_outbound_tools_are_open_world():
    tools = _tools()
    for n in ("send_mail", "reply_mail", "do_unsubscribe", "create_event"):
        assert tools[n].annotations.openWorldHint is True, n
