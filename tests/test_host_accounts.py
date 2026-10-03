"""Config resolution when there is no config.toml, which is every extension install.

The bundle ships without a TOML file. If `load_accounts` cannot build an account
from the host's `user_config` values, the extension installs perfectly and then
fails on every single tool call, which is the worst possible failure shape: it
looks like a broken product rather than a missing setting.
"""
from __future__ import annotations

import pytest

from icloud_mcp import config as cfgmod
from icloud_mcp.config import (Accounts, ConfigError, accounts_from_host,
                               load_accounts, normalize_apple_address)

MISSING = "/nonexistent/icloud-mcp/config.toml"

HOST_ENV = (cfgmod.ENV_APPLE_ID, cfgmod.ENV_APPLE_ID_2,
            cfgmod.ENV_SEND_ENABLED, cfgmod.ENV_KEYCHAIN_SERVICE)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """No host settings leak in from the machine running the tests."""
    for name in HOST_ENV:
        monkeypatch.delenv(name, raising=False)


def test_no_toml_and_no_host_names_both_fixes():
    with pytest.raises(ConfigError) as e:
        load_accounts(MISSING)
    msg = str(e.value)
    assert "Extensions" in msg          # the user's fix
    assert "config.example.toml" in msg  # the terminal fix


def test_host_apple_id_alone_is_enough(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    accts = load_accounts(MISSING)
    assert isinstance(accts, Accounts)
    assert accts.get().address == "jane@icloud.com"
    assert accts.get().imap_username == "jane"


def test_unsubstituted_placeholder_counts_as_unset(monkeypatch):
    """The template trap: a blank field arrives as its own template text."""
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "${user_config.apple_id}")
    assert accounts_from_host() is None
    with pytest.raises(ConfigError):
        load_accounts(MISSING)


def test_send_stays_off_when_toggle_is_a_placeholder(monkeypatch):
    """bool("${user_config.send_enabled}") is True. The safe default must hold."""
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_SEND_ENABLED, "${user_config.send_enabled}")
    assert load_accounts(MISSING).get().send_enabled is False


def test_send_off_by_default(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    assert load_accounts(MISSING).get().send_enabled is False


def test_send_on_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_SEND_ENABLED, "true")
    assert load_accounts(MISSING).get().send_enabled is True


def test_style_gate_off_for_strangers(monkeypatch):
    """An opinionated punctuation rule must not refuse a new user's first reply."""
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    assert load_accounts(MISSING).get().style_gate is False


def test_keychain_service_override(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_KEYCHAIN_SERVICE, "my-own-entry")
    assert load_accounts(MISSING).get().keychain_service == "my-own-entry"


def test_trusted_store_is_namespaced(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    assert load_accounts(MISSING).get().trusted_store.endswith("trusted_jane.json")


def test_second_slot_builds_a_second_account(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID_2, "jane.work@me.com")
    accts = load_accounts(MISSING)
    assert sorted(accts.names) == ["jane", "jane.work"]
    assert accts.default_name == "jane"          # slot 1 is the default
    assert accts.get("jane.work").address == "jane.work@me.com"


def test_two_accounts_never_share_a_trusted_store(monkeypatch):
    """One account's approvals must never authorise the other's sends."""
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID_2, "jane.work@me.com")
    accts = load_accounts(MISSING)
    stores = {a.trusted_store for a in accts.all()}
    assert len(stores) == 2


def test_second_slot_alone_is_ignored_without_the_first(monkeypatch):
    """Slot 2 filled and slot 1 blank still yields one usable account."""
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID_2, "jane.work@me.com")
    accts = load_accounts(MISSING)
    assert accts.names == ["jane.work"]


def test_placeholder_in_second_slot_is_ignored(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID_2, "${user_config.apple_id_2}")
    assert load_accounts(MISSING).names == ["jane"]


def test_same_short_name_on_two_domains_stays_addressable(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID_2, "jane@me.com")
    accts = load_accounts(MISSING)
    assert sorted(accts.names) == ["jane", "jane2"]
    assert accts.get("jane").address == "jane@icloud.com"
    assert accts.get("jane2").address == "jane@me.com"


def test_toml_wins_over_host(tmp_path, monkeypatch):
    """A hand-written multi-account file must survive an extension install."""
    p = tmp_path / "config.toml"
    p.write_text(
        '[accounts.main]\n'
        'address = "real@me.com"\n'
        'default = true\n'
        '[accounts.other]\n'
        'address = "second@icloud.com"\n'
    )
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    accts = load_accounts(p)
    assert sorted(accts.names) == ["main", "other"]
    assert accts.get().address == "real@me.com"


@pytest.mark.parametrize("raw,expected", [
    ("jane", "jane@icloud.com"),
    ("  Jane@ME.com  ", "jane@me.com"),
    ("JANE@MAC.COM", "jane@mac.com"),
    ("<jane@icloud.com>", "jane@icloud.com"),
])
def test_address_normalisation(raw, expected):
    assert normalize_apple_address(raw) == expected


def test_bare_at_sign_is_rejected(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "@icloud.com")
    assert accounts_from_host() is None


# --------------------------------------------------------------------------
# unpinned calendar/contacts on a multi-account setup span every account
# --------------------------------------------------------------------------
# The install form cannot express "my address book lives on the second account",
# and a user should not have to know the distinction exists. Reading only the
# default account can return a handful of contacts instead of the whole address
# book with nothing raised, a failure that is easy to miss for a long time.

def _two(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID_2, "jane.work@me.com")
    return load_accounts(MISSING)


def test_contacts_span_both_accounts_when_unpinned(monkeypatch):
    assert len(_two(monkeypatch).fanout(service="contacts")) == 2


def test_calendar_spans_both_accounts_when_unpinned(monkeypatch):
    assert len(_two(monkeypatch).fanout(service="calendar")) == 2


def test_mail_never_fans_out(monkeypatch):
    """Mail always follows the default account. Only calendar/contacts span."""
    accts = _two(monkeypatch)
    assert len(accts.fanout()) == 1
    assert accts.fanout()[0].name == "jane"


def test_single_account_does_not_span(monkeypatch):
    monkeypatch.setenv(cfgmod.ENV_APPLE_ID, "jane@icloud.com")
    assert len(load_accounts(MISSING).fanout(service="contacts")) == 1


def test_explicit_account_beats_the_default_span(monkeypatch):
    got = _two(monkeypatch).fanout("jane.work", service="contacts")
    assert [c.name for c in got] == ["jane.work"]


def test_a_pin_beats_the_default_span(tmp_path, monkeypatch):
    """config.toml stays authoritative; nobody's existing setup changes."""
    p = tmp_path / "config.toml"
    p.write_text(
        '[accounts.main]\naddress = "a@me.com"\ndefault = true\n'
        '[accounts.work]\naddress = "b@icloud.com"\n'
        '[contacts]\naccount = "work"\n'
    )
    got = load_accounts(p).fanout(service="contacts")
    assert [c.name for c in got] == ["work"]


def test_writes_still_refuse_to_fan_out(monkeypatch):
    """A create must never duplicate itself across accounts."""
    accts = _two(monkeypatch)
    assert accts.require_one(service="calendar").name == "jane"
    with pytest.raises(ConfigError):
        accts.require_one("all", service="calendar")
