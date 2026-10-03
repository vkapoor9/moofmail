"""Read config injected by an MCPB host (Claude Desktop `user_config`).

A `.mcpb` manifest wires settings into the server process through variable
substitution:

    "env": { "ICLOUD_APP_PASSWORD": "${user_config.app_password}" }

**A blank optional field is not delivered as an empty string. The literal
template text arrives instead.** Verified against Claude
Desktop 1.24012.9: a probe bundle installed with both fields left blank reported
`secret_arrived: true, secret_len: 27`, because "${user_config.probe_secret}" is
27 characters and `bool()` is perfectly happy with it.

Nothing here trusts an environment variable it was handed. Two failures this
prevents, both of which look like success:

  * a placeholder reaching IMAP as if it were the app-specific password, so the
    user troubleshoots a credential they never set
  * `bool("${user_config.send_enabled}")` being True, which turns an UNSET send
    toggle ON. A safety default must never invert itself in silence.
"""
from __future__ import annotations

import os
import re

# Matches ONLY a whole, unsubstituted user_config placeholder. Deliberately not
# a substring search: a real password may contain braces or a dollar sign, and
# silently dropping a valid credential is its own outage.
_PLACEHOLDER = re.compile(r"^\$\{user_config\.[A-Za-z0-9_]+\}$")

_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}

# Apple app-specific passwords are 16 letters in four groups: abcd-efgh-ijkl-mnop.
_APPLE_PW = re.compile(r"^[a-z]{16}$")


def is_placeholder(value: str | None) -> bool:
    """True when the host left a `user_config` field unsubstituted."""
    return bool(value) and bool(_PLACEHOLDER.match(value.strip()))


def get_str(name: str) -> str | None:
    """Environment value, or None when unset, blank, or an unsubstituted placeholder."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    raw = raw.strip()
    if not raw or is_placeholder(raw):
        return None
    return raw


def get_bool(name: str, default: bool) -> bool:
    """Parse a boolean from an explicit allowlist, else return `default`.

    Anything unrecognised (a placeholder, an empty string, "banana") keeps the
    default rather than being coerced. For `send_enabled` the default is False,
    so an unset or malformed value leaves sending OFF.
    """
    raw = get_str(name)
    if raw is None:
        return default
    low = raw.lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    return default


def normalize_app_password(value: str | None) -> str | None:
    """Tidy a pasted app-specific password without ever reshaping something else.

    Handles the ways people actually paste them: trailing newlines, no dashes,
    spaces instead of dashes, and upper case. Anything not matching Apple's known
    16-letter format is returned trimmed but otherwise untouched, because a hard
    format check would break every install the day Apple changes it. Shape advice
    belongs in the diagnose tool, where it can be advisory instead of fatal.
    """
    if value is None:
        return None
    v = value.strip()
    if not v:
        return v
    compact = re.sub(r"[\s-]", "", v).lower()
    if _APPLE_PW.match(compact):
        return "-".join(compact[i:i + 4] for i in range(0, 16, 4))
    return v
