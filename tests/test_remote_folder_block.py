"""Can the remote connector reach mail folders it was never meant to?

Found when the owner asked whether Notes were exposed. They were. Apple
stores iCloud Notes as ordinary IMAP folders (`Notes`, `Notes/Taxes`, ...),
and every mail tool takes a free-text `folder` parameter, so "read-only access to
mail" quietly meant "read-only access to every IMAP collection on the account",
Notes included. Verified live before the fix: real note titles came back.

The threat model said "mail, calendar and contacts" and nobody asked what
`folder=` could point at. This blocks Notes on the REMOTE surface only; local
sessions keep full access.

Two layers on purpose:
  - `list_folders` hides them, so the model never sees them to try, and
  - every folder-taking tool refuses them, because hiding is not a control when
    the parameter is free text and the caller may be reading a stranger's email.
"""
from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from icloud_mcp import remote

BLOCKED = ["Notes", "Notes/Taxes", "Notes/Work", "notes/travel"]
ALLOWED = ["INBOX", "Archive", "Sent Messages", "Drafts", "Bank Statements",
           "Travel Plans", "Notestalgia", "My Notes"]


@pytest.mark.parametrize("folder", BLOCKED)
def test_blocked_folders_are_recognised(folder):
    assert remote.is_blocked(folder), f"{folder!r} should be blocked"


@pytest.mark.parametrize("folder", ALLOWED)
def test_everything_else_is_allowed(folder):
    """The owner chose Notes only. A blocklist that quietly grows is worse than one
    that does exactly what was agreed. 'Notestalgia' must NOT match 'Notes'."""
    assert not remote.is_blocked(folder), f"{folder!r} should NOT be blocked"


@pytest.mark.parametrize("tool", ["list_inbox", "search_mail", "get_message",
                                  "draft_reply", "find_unsubscribe"])
def test_every_folder_taking_tool_refuses_a_blocked_folder(tool):
    """Refusal must happen BEFORE any IMAP call, so a blocked folder is never
    even opened."""
    fn = getattr(remote, tool)
    args = {"list_inbox": (), "search_mail": ("q",), "get_message": (1,),
            "draft_reply": (1, "say thanks"), "find_unsubscribe": (1,)}[tool]
    with pytest.raises(ToolError, match="not available"):
        fn(*args, folder="Notes/Taxes")


def test_list_folders_hides_blocked_folders(monkeypatch):
    monkeypatch.setattr(remote.server, "list_folders",
                        lambda account=None: ["INBOX", "Notes", "Notes/Taxes",
                                              "Archive", "Notestalgia"])
    out = remote.list_folders()
    assert out == ["INBOX", "Archive", "Notestalgia"]


def test_the_blocking_wrappers_are_what_gets_registered():
    """A wrapper that exists but is not registered protects nothing."""
    import asyncio
    srv = remote.build_server()
    assert "list_inbox" in {t.name for t in asyncio.run(srv.list_tools())}
    assert remote._OVERRIDES["list_inbox"] is remote.list_inbox


def test_local_server_is_untouched():
    """Blocking is a REMOTE-surface decision. Local sessions keep full access."""
    from icloud_mcp import server
    assert not hasattr(server.list_inbox, "_blocks_folders")


def test_every_wrapper_signature_matches_the_function_it_wraps():
    """The bug this guards, made 2026-09-22 and caught only by a live call.

    The blocking wrappers re-declare each tool's signature so FastMCP can build
    the argument schema from it. I wrote those signatures from memory and
    invented two parameters that do not exist (`exclude_bulk` on list_inbox,
    `since_days` on search_mail). Every unit test still passed, because they only
    exercised the REFUSAL path, which returns before calling through. The first
    real call died with TypeError.

    create_event is the one intentional difference: `attendees` is removed.
    """
    import inspect
    from icloud_mcp import server

    intentional_removals = {"create_event": {"attendees"}}

    for name, wrapper in remote._OVERRIDES.items():
        theirs = set(inspect.signature(getattr(server, name)).parameters)
        mine = set(inspect.signature(wrapper).parameters)
        expected = theirs - intentional_removals.get(name, set())
        assert mine == expected, (
            f"{name}: wrapper takes {sorted(mine)}, wrapped function takes "
            f"{sorted(expected)}; invented={sorted(mine - expected)}, "
            f"missing={sorted(expected - mine)}"
        )
