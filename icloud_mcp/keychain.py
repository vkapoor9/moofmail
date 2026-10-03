"""Resolve the app-specific password, from the MCPB host or the macOS Keychain.

Two ways in, checked in this order:

1. **Host-injected** (`ICLOUD_APP_PASSWORD`), when the server was launched by a
   `.mcpb` extension. Claude Desktop stores the value in the OS keychain and
   substitutes it into this process. Works on macOS and Windows.
2. **macOS Keychain** directly, read with `security` at connection time:

       security add-generic-password -s icloud-mcp -a <imap_username> -w

Path 2 is what a privacy-maximalist user wants, because the credential never
passes through the extension's settings at all. `ICLOUD_USE_OWN_KEYCHAIN=true`
forces it, and it is the only path on a hand-built install.

The secret is NEVER written to a file, logged, or placed in config. Only read.

Two guards that are not optional, both found the hard way:

* **A placeholder is not a password.** An unset `user_config` field arrives as the
  literal "${user_config.app_password}", not as an empty string. See hostcfg.py.
* **A host password belongs to ONE account.** The extension configures a single
  Apple Account while config.toml may define several, so the injected credential
  is only ever used for the account named in `ICLOUD_APPLE_ID`. Same reasoning as
  the per-account trusted recipient stores: one account's credential must never
  reach another's mailbox.
"""
from __future__ import annotations

import subprocess

from . import hostcfg

SERVICE = "icloud-mcp"

ENV_PASSWORD = "ICLOUD_APP_PASSWORD"
ENV_APPLE_ID = "ICLOUD_APPLE_ID"
ENV_USE_OWN_KEYCHAIN = "ICLOUD_USE_OWN_KEYCHAIN"

# The install form has no repeating groups (MCPB `multiple` covers file and
# directory pickers only), so a second account means a second explicit pair of
# fields. Pairs are matched by POSITION: slot 2's password belongs to slot 2's
# address and to nothing else.
ENV_PAIRS = ((ENV_APPLE_ID, ENV_PASSWORD),
             ("ICLOUD_APPLE_ID_2", "ICLOUD_APP_PASSWORD_2"))


class KeychainError(RuntimeError):
    pass


def _short_username(address: str) -> str:
    """iCloud's IMAP username is the part before '@'."""
    return address.split("@", 1)[0].strip().lower()


def _host_password(account: str) -> str | None:
    """Host-injected password, but only for the account it actually belongs to.

    Walks every configured slot and returns the password whose PAIRED address
    matches `account`. None when the host path is disabled, when nothing is set,
    when the value is still an unsubstituted placeholder, or when no slot names
    this account.

    The pairing is the safety property, not a detail. A password that applies to
    whichever account happens to ask is a password that reaches a mailbox its
    owner never authorised, which is the same reasoning behind per-account
    trusted-recipient stores.
    """
    if hostcfg.get_bool(ENV_USE_OWN_KEYCHAIN, False):
        return None
    want = account.strip().lower()
    for id_var, pw_var in ENV_PAIRS:
        pw = hostcfg.get_str(pw_var)
        if pw is None:
            continue
        apple_id = hostcfg.get_str(id_var)
        if apple_id is None:
            # Without knowing whose password this is, it is unusable rather than
            # universal. Refusing here is what keeps it off other accounts.
            continue
        if _short_username(apple_id) != want:
            continue
        return hostcfg.normalize_app_password(pw)
    return None


def _read_keychain(account: str, service: str) -> str | None:
    """Read the item from the macOS Keychain, or None if absent or unavailable."""
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        # Not macOS. Normal on Windows, where the host path is the only one.
        return None
    except subprocess.TimeoutExpired as e:
        raise KeychainError("Keychain lookup timed out") from e
    if out.returncode != 0:
        return None
    return out.stdout.rstrip("\n") or None


def get_password(account: str, service: str = SERVICE) -> str:
    """Return the app-specific password for `account`.

    Raises KeychainError naming BOTH ways to fix it, because the user who hit
    this may never have opened a terminal.
    """
    pw = _host_password(account)
    if pw:
        return pw
    pw = _read_keychain(account, service)
    if pw:
        return pw
    raise KeychainError(
        f"No app-specific password for '{account}'. Either paste one into the "
        f"extension settings in Claude, or add it to the Keychain with: "
        f"security add-generic-password -s {service} -a {account} -w"
    )


def has_password(account: str, service: str = SERVICE) -> bool:
    """True if a usable password exists. Never returns or logs the secret."""
    if _host_password(account):
        return True
    return _read_keychain(account, service) is not None


def password_source(account: str, service: str = SERVICE) -> str:
    """Where the password came from: "host", "keychain" or "missing".

    For the diagnose tool. Reports the path, never the secret, so its output stays
    safe to paste into a bug report.
    """
    if _host_password(account):
        return "host"
    if _read_keychain(account, service) is not None:
        return "keychain"
    return "missing"
