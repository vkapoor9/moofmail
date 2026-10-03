"""Note bodies must never reach a model context, on ANY surface.

iCloud Notes are confidential by design decision: mailbox content is fair game
for the tools, note bodies are not, and they should never leave the machine.

Blocking Notes on a remote transport only would not be enough. Every local MCP
client talks to the same stdio server, and every one of those sends whatever it
reads into a model context. So the block belongs in server.py, where every
surface passes through, not in any one transport.

The check lives inside _guard, the decorator every tool already uses, so it
covers all 33 tools and any tool added later without someone remembering to wire
it up. move_message is checked on BOTH folder and dest_folder: reading out of
Notes and filing mail into Notes are both refused.
"""
from __future__ import annotations

import inspect

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from icloud_mcp import server

FOLDER_TOOLS = ["archive", "do_unsubscribe", "draft_reply", "find_unsubscribe",
                "flag", "get_message", "list_inbox", "mark_read", "move_message",
                "reply_mail", "search_mail", "trash"]


@pytest.mark.parametrize("name", FOLDER_TOOLS)
def test_every_folder_tool_refuses_notes(name):
    """Refusal must happen before any network call, so nothing is even opened."""
    fn = getattr(server, name)
    args = {
        "archive": (1,), "do_unsubscribe": (1,), "draft_reply": (1, "x"),
        "find_unsubscribe": (1,), "flag": (1,), "get_message": (1,),
        "list_inbox": (), "mark_read": (1,), "move_message": (1, "Archive"),
        "reply_mail": (1, "body"), "search_mail": ("q",), "trash": ([1],),
    }[name]
    with pytest.raises(ToolError, match="not available"):
        fn(*args, folder="Notes/Recipes")


def test_mail_cannot_be_moved_INTO_notes():
    """dest_folder is checked too, not just the source."""
    with pytest.raises(ToolError, match="not available"):
        server.move_message(1, dest_folder="Notes", folder="INBOX")


@pytest.mark.parametrize("folder", ["Notes", "Notes/Recipes", "notes/travel",
                                    "NOTES", "Notes/Journal"])
def test_blocked_names(folder):
    assert server.folder_blocked(folder)


@pytest.mark.parametrize("folder", ["INBOX", "Archive", "Receipts",
                                    "Travel Plans", "Notestalgia", "My Notes"])
def test_mail_folders_stay_open(folder):
    """Ordinary mail folders are deliberately open. Only Notes is confidential,
    and 'Notes' must not swallow 'Notestalgia'."""
    assert not server.folder_blocked(folder)


def test_list_folders_hides_notes(monkeypatch):
    monkeypatch.setattr(server, "_folder_names",
                        lambda account=None: ["INBOX", "Notes", "Notes/Recipes",
                                              "Archive", "Notestalgia"])
    assert server.list_folders() == ["INBOX", "Archive", "Notestalgia"]


def test_the_check_is_inside_guard_so_new_tools_inherit_it():
    """If someone adds a 34th tool taking a folder, it is protected without them
    remembering anything. This asserts the mechanism, not each call site."""
    src = inspect.getsource(server._guard)
    assert "_check_folders" in src, "_guard no longer enforces the folder block"
