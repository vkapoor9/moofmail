"""Credential resolution when the server is launched by an MCPB host.

Order is: host-injected password (Claude Desktop `user_config`) first, Keychain
second. Two things must hold no matter what the host hands us.

1. A placeholder is not a password. See test_hostcfg.py for the live finding.
2. **A host password belongs to exactly ONE account.** The extension configures a
   single Apple Account, but config.toml may define several. Handing the injected
   credential to a different account would attempt one account's password against
   another's mailbox, which is the same class of mistake as sharing a trusted
   recipient store across accounts.
"""
from __future__ import annotations

import pytest

from icloud_mcp import keychain


@pytest.fixture(autouse=True)
def no_real_keychain(monkeypatch):
    """Never shell out to `security` in tests. Default: nothing in the Keychain."""
    monkeypatch.setattr(keychain, "_read_keychain", lambda a, s: None)
    for var in ("ICLOUD_APP_PASSWORD", "ICLOUD_APPLE_ID", "ICLOUD_USE_OWN_KEYCHAIN",
                "ICLOUD_APP_PASSWORD_2", "ICLOUD_APPLE_ID_2"):
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------------
# two slots: pairing by position, and never across
# --------------------------------------------------------------------------

def test_each_slot_serves_only_its_own_account(monkeypatch):
    monkeypatch.setenv("ICLOUD_APPLE_ID", "jane@icloud.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", "aaaa-aaaa-aaaa-aaaa")
    monkeypatch.setenv("ICLOUD_APPLE_ID_2", "jane.work@me.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD_2", "bbbb-bbbb-bbbb-bbbb")
    assert keychain.get_password("jane") == "aaaa-aaaa-aaaa-aaaa"
    assert keychain.get_password("jane.work") == "bbbb-bbbb-bbbb-bbbb"


def test_slot_two_password_never_reaches_an_unnamed_account(monkeypatch):
    """The whole point of pairing: a stranger's mailbox gets nothing."""
    monkeypatch.setenv("ICLOUD_APPLE_ID_2", "jane.work@me.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD_2", "bbbb-bbbb-bbbb-bbbb")
    with pytest.raises(keychain.KeychainError):
        keychain.get_password("someone.else")


def test_slot_two_works_when_slot_one_is_blank(monkeypatch):
    monkeypatch.setenv("ICLOUD_APPLE_ID", "${user_config.apple_id}")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", "${user_config.app_password}")
    monkeypatch.setenv("ICLOUD_APPLE_ID_2", "jane.work@me.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD_2", "bbbb-bbbb-bbbb-bbbb")
    assert keychain.get_password("jane.work") == "bbbb-bbbb-bbbb-bbbb"


def test_own_keychain_switch_disables_every_slot(monkeypatch):
    monkeypatch.setenv("ICLOUD_USE_OWN_KEYCHAIN", "true")
    monkeypatch.setenv("ICLOUD_APPLE_ID", "jane@icloud.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", "aaaa-aaaa-aaaa-aaaa")
    monkeypatch.setenv("ICLOUD_APPLE_ID_2", "jane.work@me.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD_2", "bbbb-bbbb-bbbb-bbbb")
    with pytest.raises(keychain.KeychainError):
        keychain.get_password("jane")
    with pytest.raises(keychain.KeychainError):
        keychain.get_password("jane.work")


def test_slot_two_password_normalised_like_slot_one(monkeypatch):
    monkeypatch.setenv("ICLOUD_APPLE_ID_2", "jane.work@me.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD_2", "  BBBBBBBBBBBBBBBB\n")
    assert keychain.get_password("jane.work") == "bbbb-bbbb-bbbb-bbbb"


def _host(monkeypatch, pw="abcd-efgh-ijkl-mnop", apple_id="jane@icloud.com"):
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", pw)
    monkeypatch.setenv("ICLOUD_APPLE_ID", apple_id)


# --------------------------------------------------------------------------
# the host path
# --------------------------------------------------------------------------

def test_host_password_used_for_its_own_account(monkeypatch):
    _host(monkeypatch)
    assert keychain.get_password("jane", "icloud-mcp") == "abcd-efgh-ijkl-mnop"


def test_host_password_is_normalised(monkeypatch):
    _host(monkeypatch, pw="  ABCDEFGHIJKLMNOP \n")
    assert keychain.get_password("jane", "icloud-mcp") == "abcd-efgh-ijkl-mnop"


def test_full_address_matches_short_username(monkeypatch):
    """`account` is the IMAP short name; ICLOUD_APPLE_ID is the full address."""
    _host(monkeypatch, apple_id="Jane@ICLOUD.com")
    assert keychain.get_password("jane", "icloud-mcp") == "abcd-efgh-ijkl-mnop"


# --------------------------------------------------------------------------
# the guards
# --------------------------------------------------------------------------

def test_placeholder_password_is_not_a_password(monkeypatch):
    """THE bug. Must fall through to the Keychain, not log in with template text."""
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", "${user_config.app_password}")
    monkeypatch.setenv("ICLOUD_APPLE_ID", "jane@icloud.com")
    with pytest.raises(keychain.KeychainError):
        keychain.get_password("jane", "icloud-mcp")
    assert keychain.has_password("jane", "icloud-mcp") is False


def test_placeholder_apple_id_does_not_authorise_anyone(monkeypatch):
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", "abcd-efgh-ijkl-mnop")
    monkeypatch.setenv("ICLOUD_APPLE_ID", "${user_config.apple_id}")
    with pytest.raises(keychain.KeychainError):
        keychain.get_password("jane", "icloud-mcp")


def test_host_password_never_leaks_to_another_account(monkeypatch):
    """Injected credential is for jane. Asking for bob must NOT return it."""
    _host(monkeypatch, apple_id="jane@icloud.com")
    monkeypatch.setattr(
        keychain, "_read_keychain",
        lambda a, s: "bobs-own-keychain-pw" if a == "bob" else None,
    )
    assert keychain.get_password("bob", "icloud-mcp") == "bobs-own-keychain-pw"
    assert keychain.get_password("jane", "icloud-mcp") == "abcd-efgh-ijkl-mnop"


def test_missing_apple_id_disables_the_host_path(monkeypatch):
    """Without knowing who it belongs to, the password is unusable, not universal."""
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", "abcd-efgh-ijkl-mnop")
    with pytest.raises(keychain.KeychainError):
        keychain.get_password("jane", "icloud-mcp")


def test_use_own_keychain_toggle_skips_the_host_password(monkeypatch):
    _host(monkeypatch)
    monkeypatch.setenv("ICLOUD_USE_OWN_KEYCHAIN", "true")
    monkeypatch.setattr(keychain, "_read_keychain", lambda a, s: "from-keychain")
    assert keychain.get_password("jane", "icloud-mcp") == "from-keychain"


def test_toggle_placeholder_does_not_disable_the_host_path(monkeypatch):
    """An unsubstituted toggle must read as its default (False), not as True."""
    _host(monkeypatch)
    monkeypatch.setenv("ICLOUD_USE_OWN_KEYCHAIN", "${user_config.use_own_keychain_entry}")
    assert keychain.get_password("jane", "icloud-mcp") == "abcd-efgh-ijkl-mnop"


# --------------------------------------------------------------------------
# fallback and reporting
# --------------------------------------------------------------------------

def test_keychain_still_works_with_no_host_config(monkeypatch):
    monkeypatch.setattr(keychain, "_read_keychain", lambda a, s: "classic")
    assert keychain.get_password("jane", "icloud-mcp") == "classic"
    assert keychain.has_password("jane", "icloud-mcp") is True


def test_error_names_both_paths(monkeypatch):
    """The user may have set neither; the message must not assume a terminal."""
    with pytest.raises(keychain.KeychainError) as e:
        keychain.get_password("jane", "icloud-mcp")
    msg = str(e.value)
    assert "extension settings" in msg.lower()
    assert "security add-generic-password" in msg


def test_source_reports_where_it_came_from(monkeypatch):
    """diagnose needs this, and it must never return the secret itself."""
    assert keychain.password_source("jane", "icloud-mcp") == "missing"
    monkeypatch.setattr(keychain, "_read_keychain", lambda a, s: "classic")
    assert keychain.password_source("jane", "icloud-mcp") == "keychain"
    _host(monkeypatch)
    assert keychain.password_source("jane", "icloud-mcp") == "host"
