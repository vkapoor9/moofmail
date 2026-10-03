"""What the remote (read-only) connector is allowed to do, and what it cannot express.

The bug these guard is the one this whole posture exists to prevent: a tool that
can put data OUT of the mailbox being reachable from an internet endpoint, where
the thing deciding to call it is a model reading attacker-controlled email.

The distinction that matters is ABSENT vs GATED. Several tools in server.py are
"safe by default" only because of a parameter the CALLER picks: apply_rules
defaults dry_run=True, delete_event and send_mail default confirm=False. When the
caller is a model under prompt injection, a default it chooses is not a control.
So the remote profile must not register them at all.

create_event is the one deliberate exception, carved in on 2026-09-21 so the
auto-calendar rule keeps working from a phone. Its `attendees` parameter is an
outbound mail channel in a calendar costume (iCloud emails real invitations), so
the remote wrapper must not have that parameter AT ALL. Not defaulted to None.
Absent, so no caller can express it.

No network: nothing here calls a tool, it only inspects what was registered.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

from icloud_mcp import remote, server


def _registered_names(srv) -> set[str]:
    return {t.name for t in asyncio.run(srv.list_tools())}


# ---- the tools that must never be reachable from the internet ----
FORBIDDEN = [
    "send_mail",          # outbound channel, the whole point
    "reply_mail",         # outbound channel
    "do_unsubscribe",     # mailto path SENDS mail from the owner's account
    "trash",              # destructive
    "bulk_trash",         # destructive at scale
    "recover_from_trash", # moves mail around in bulk
    "move_message",       # can hide mail from its owner
    "archive",            # same
    "apply_rules",        # dry_run=True is a MODEL-chosen default, not a control
    "delete_event",       # CalDAV has no Trash; deletion is final
    "update_event",       # can rewrite an existing event's attendees
    "mark_read",          # stealth primitive: injected mail can hide itself
    "flag",               # mutates state
    "reset_trusted_recipients",  # would let a remote session widen the send gate
]


@pytest.mark.parametrize("name", FORBIDDEN)
def test_remote_profile_does_not_register_write_tools(name):
    assert name not in _registered_names(remote.build_server()), (
        f"{name} is reachable over the remote connector"
    )


def test_remote_profile_registers_the_reads():
    names = _registered_names(remote.build_server())
    for expected in ("list_inbox", "search_mail", "get_message", "triage_inbox",
                     "morning_brief", "agenda", "search_contacts", "draft_reply",
                     "status", "free_slots", "sender_census", "cleanup_preview"):
        assert expected in names, f"{expected} missing from the remote profile"


def test_remote_create_event_cannot_express_attendees():
    """An attendee list makes iCloud email a real invitation. The remote
    signature must have no parameter that can carry one."""
    names = _registered_names(remote.build_server())
    assert "create_event" in names, "create_event was carved in on 2026-09-21"

    params = inspect.signature(remote.create_event).parameters
    assert "attendees" not in params, (
        "remote create_event still exposes `attendees`, which is an outbound "
        "mail channel wearing a calendar costume"
    )
    # the local one still has it, so this test is proving a real difference
    assert "attendees" in inspect.signature(server.create_event).parameters


def test_every_server_tool_is_classified():
    """A 34th tool added to server.py must be consciously placed in one list or
    the other. This is what stops a future write tool drifting in unnoticed."""
    all_tools = _registered_names(server.mcp)
    classified = (set(remote.REMOTE_TOOLS) | set(remote.REMOTE_WRITE_TOOLS)
                  | set(remote.EXCLUDED_TOOLS))
    assert all_tools == classified, (
        f"unclassified: {all_tools - classified}; "
        f"listed but nonexistent: {classified - all_tools}"
    )


def test_allowlist_and_excluded_list_do_not_overlap():
    r, w, x = set(remote.REMOTE_TOOLS), set(remote.REMOTE_WRITE_TOOLS), set(remote.EXCLUDED_TOOLS)
    assert not (r & x) and not (w & x) and not (r & w)


def test_remote_profile_is_smaller_than_the_local_one():
    assert len(_registered_names(remote.build_server())) < len(_registered_names(server.mcp))
