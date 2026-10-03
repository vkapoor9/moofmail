"""Host-injected config (MCPB `user_config`) must never trust what it is handed.

Found with a probe bundle installed into Claude Desktop 1.24012.9:
a `user_config` field left blank is NOT delivered as an empty string. The literal
template text arrives instead. The probe reported `secret_arrived: true, len=27`
with nothing entered, because "${user_config.probe_secret}" is 27 characters and a
plain truthiness check passed on it.

Two consequences these tests lock down:
  * a placeholder password would be sent to IMAP as if it were a real credential
  * "${user_config.send_enabled}" is a non-empty string, so a naive bool() reads an
    UNSET send toggle as ON. That is a safety default inverting itself silently.
"""
from __future__ import annotations

import pytest

from icloud_mcp import hostcfg


# --------------------------------------------------------------------------
# get_str
# --------------------------------------------------------------------------

def test_unset_is_none(monkeypatch):
    monkeypatch.delenv("X_THING", raising=False)
    assert hostcfg.get_str("X_THING") is None


@pytest.mark.parametrize("raw", ["", "   ", "\n", "\t "])
def test_blank_is_none(monkeypatch, raw):
    monkeypatch.setenv("X_THING", raw)
    assert hostcfg.get_str("X_THING") is None


@pytest.mark.parametrize("raw", [
    "${user_config.probe_secret}",      # the exact 27-char value seen live
    "${user_config.app_password}",
    "${user_config.a}",
    "  ${user_config.app_password}  ",  # host may pad it
])
def test_placeholder_is_none(monkeypatch, raw):
    monkeypatch.setenv("X_THING", raw)
    assert hostcfg.get_str("X_THING") is None


def test_the_exact_live_failure(monkeypatch):
    """The literal case the probe returned, asserted end to end."""
    raw = "${user_config.probe_secret}"
    assert len(raw) == 27          # why bool() looked like a real 27-char secret
    monkeypatch.setenv("X_THING", raw)
    assert hostcfg.get_str("X_THING") is None


def test_real_value_survives(monkeypatch):
    monkeypatch.setenv("X_THING", "  abcd-efgh-ijkl-mnop \n")
    assert hostcfg.get_str("X_THING") == "abcd-efgh-ijkl-mnop"


@pytest.mark.parametrize("raw", [
    "pre${user_config.x}post",   # merely contains a placeholder
    "${something_else.x}",       # not a user_config placeholder
    "${user_config.x} ${user_config.y}",
    "$" "{user_config.x",        # unterminated
])
def test_only_a_whole_placeholder_is_rejected(monkeypatch, raw):
    """Do not over-match. A password may legitimately contain odd characters."""
    monkeypatch.setenv("X_THING", raw)
    assert hostcfg.get_str("X_THING") == raw.strip()


# --------------------------------------------------------------------------
# get_bool  (the safety-relevant one)
# --------------------------------------------------------------------------

def test_placeholder_bool_falls_back_to_default(monkeypatch):
    """THE bug: an unset send toggle must not read as ON."""
    monkeypatch.setenv("X_FLAG", "${user_config.send_enabled}")
    assert hostcfg.get_bool("X_FLAG", False) is False
    assert bool("${user_config.send_enabled}") is True   # what we are defending against


@pytest.mark.parametrize("raw", ["true", "TRUE", "  True ", "1", "yes", "on"])
def test_truthy_words(monkeypatch, raw):
    monkeypatch.setenv("X_FLAG", raw)
    assert hostcfg.get_bool("X_FLAG", False) is True


@pytest.mark.parametrize("raw", ["false", "FALSE", "0", "no", "off", " Off "])
def test_falsy_words(monkeypatch, raw):
    monkeypatch.setenv("X_FLAG", raw)
    assert hostcfg.get_bool("X_FLAG", True) is False


@pytest.mark.parametrize("raw", ["", "maybe", "banana", "${user_config.x}", "2"])
def test_unrecognised_uses_default_both_ways(monkeypatch, raw):
    """Anything we do not positively recognise must not flip the default."""
    monkeypatch.setenv("X_FLAG", raw)
    assert hostcfg.get_bool("X_FLAG", False) is False
    assert hostcfg.get_bool("X_FLAG", True) is True


def test_unset_uses_default(monkeypatch):
    monkeypatch.delenv("X_FLAG", raising=False)
    assert hostcfg.get_bool("X_FLAG", False) is False
    assert hostcfg.get_bool("X_FLAG", True) is True


# --------------------------------------------------------------------------
# app-specific password normalisation
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,want", [
    ("abcd-efgh-ijkl-mnop", "abcd-efgh-ijkl-mnop"),
    ("abcdefghijklmnop", "abcd-efgh-ijkl-mnop"),   # typed without dashes
    ("  abcd-efgh-ijkl-mnop  ", "abcd-efgh-ijkl-mnop"),
    ("ABCD-EFGH-IJKL-MNOP", "abcd-efgh-ijkl-mnop"),  # Apple issues lowercase
    ("abcd efgh ijkl mnop", "abcd-efgh-ijkl-mnop"),  # pasted from a PDF
])
def test_password_normalisation(raw, want):
    assert hostcfg.normalize_app_password(raw) == want


@pytest.mark.parametrize("raw", [
    "hunter2",                       # a real Apple password: leave alone, do not mangle
    "not-an-app-specific-password",
    "abcd-efgh-ijkl",                # too short
    "abcd1-efgh-ijkl-mnop",
    "",
])
def test_non_apple_shapes_pass_through_untouched(raw):
    """Never reshape something that is not the known 16-letter format.

    Blocking on shape is deliberately NOT done here: if Apple ever changes the
    format, a hard check would break every install at once. Shape advice belongs
    in the diagnose tool, where it is advisory.
    """
    assert hostcfg.normalize_app_password(raw) == raw.strip()


def test_normalising_none_is_none():
    assert hostcfg.normalize_app_password(None) is None
