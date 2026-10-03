"""Load and validate iCloud MCP's non-secret config (TOML).

No secrets here, the app-specific password comes from Keychain (see keychain.py).
Uses stdlib tomllib (Python 3.11+).
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo

from . import hostcfg

DEFAULT_PATH = "~/.config/icloud-mcp/config.toml"

# Host-injected settings, set by a .mcpb manifest's `user_config` substitution.
ENV_APPLE_ID = "ICLOUD_APPLE_ID"
ENV_APPLE_ID_2 = "ICLOUD_APPLE_ID_2"
ENV_SEND_ENABLED = "ICLOUD_SEND_ENABLED"
ENV_KEYCHAIN_SERVICE = "ICLOUD_KEYCHAIN_SERVICE"

# Address slots in the install form, in order. The first is the default account.
# Two is the deliberate cap: the manifest format has no repeating groups, so each
# extra account is two more hardcoded fields, and past two a form stops being the
# right tool. Anyone with three accounts wants config.toml.
ENV_ADDRESS_SLOTS = (ENV_APPLE_ID, ENV_APPLE_ID_2)

# Domains Apple issues addresses on, tried in order when someone types only the
# part before the '@'. Guessing beats refusing: a wrong guess fails at login with
# a clear message, whereas refusing to start hides the mistake behind a config error.
_APPLE_DOMAINS = ("icloud.com", "me.com", "mac.com")


def system_timezone() -> ZoneInfo:
    """The machine's local zone as a named ZoneInfo, falling back to UTC.

    A NAMED zone matters: event writes emit `TZID=<key>`, and a bare fixed
    offset (what `datetime.now().astimezone()` gives) would pin every event to
    today's offset and drift by an hour across a DST change. Order: the `TZ`
    environment variable, then the `/etc/localtime` symlink (macOS and most
    Linux), then UTC.
    """
    env = os.environ.get("TZ", "").strip().lstrip(":")
    candidates = [env] if env else []
    try:
        real = os.path.realpath("/etc/localtime")
        if "/zoneinfo/" in real:
            candidates.append(real.rsplit("/zoneinfo/", 1)[1])
    except OSError:
        pass
    for key in candidates:
        try:
            return ZoneInfo(key)
        except Exception:  # noqa: BLE001 - bad TZ values fall through to the next source
            continue
    return ZoneInfo("UTC")


def resolve_timezone(name: str | None) -> ZoneInfo:
    """`[calendar].timezone` as a ZoneInfo. Empty or invalid means system local."""
    key = (name or "").strip()
    if key:
        try:
            return ZoneInfo(key)
        except Exception:  # noqa: BLE001 - a typo must not take the calendar down
            pass
    return system_timezone()


@dataclass
class TriageRule:
    match: str
    priority: str = "normal"  # high | normal | low


@dataclass
class CleanupRule:
    match: str
    action: str            # archive | move | mark_read | delete
    folder: str | None = None


@dataclass
class Config:
    """Settings for ONE mail account. Shared settings are copied into each."""
    address: str
    name: str = "default"
    # Keychain lookup. Distinct services let several accounts coexist on one Mac.
    keychain_service: str = "icloud-mcp"
    keychain_account_override: str | None = None
    # Hard guardrail: an account that must never send (a read-only or
    # archive-only Apple ID) is enforced in code rather than remembered.
    send_enabled: bool = True
    # Optional outbound style gate: blocks characters that read as
    # machine-written (see scrub.py). On by default for config.toml installs;
    # a host-installed extension turns it off so a new user's first reply is
    # not refused over an em dash.
    style_gate: bool = True
    window_days: int = 7
    max_messages: int = 200
    exclude_bulk: bool = True
    brief_hour: int = 8
    brief_minute: int = 0
    brief_folders: list[str] = field(default_factory=lambda: ["INBOX"])
    trusted_store: str = "~/.local/state/icloud-mcp/trusted_recipients.json"
    allow_delete: bool = False
    # Addresses a bulk cleanup must never delete, however high they rank by
    # volume. People you correspond with a lot sort to the TOP of a volume scan,
    # which is exactly the trap. Lives in config, not code, because the list is
    # personal and config.toml is gitignored.
    protected_senders: list[str] = field(default_factory=list)
    triage_rules: list[TriageRule] = field(default_factory=list)
    cleanup_rules: list[CleanupRule] = field(default_factory=list)
    # Calendars feeding the brief and the default agenda. Empty = every calendar.
    calendar_include: list[str] = field(default_factory=list)
    calendar_write: str = ""
    # IANA zone name, e.g. "America/New_York". Empty means the machine's local
    # zone, resolved at use time by resolve_timezone().
    calendar_timezone: str = ""
    # Which account holds the calendars and the address book. Mail, calendar and
    # contacts do not have to live together: the configured calendar names and
    # the real address book may sit on one account while mail is read from
    # another. Empty means "use the default account".
    calendar_account: str = ""
    contacts_account: str = ""

    @property
    def imap_username(self) -> str:
        """iCloud IMAP username is the part before '@'."""
        return self.address.split("@", 1)[0]

    @property
    def keychain_account(self) -> str:
        return self.keychain_account_override or self.imap_username

    @property
    def trusted_store_path(self) -> Path:
        return Path(os.path.expanduser(self.trusted_store))


# Services that can be pinned to an account other than the mail default, and the
# Config field carrying that choice. Mail is absent on purpose: it always follows
# the default account.
_SERVICE_ATTR = {"calendar": "calendar_account", "contacts": "contacts_account"}


@dataclass
class Accounts:
    """Every configured account, plus which one is the default."""
    accounts: dict[str, Config]
    default_name: str

    @property
    def names(self) -> list[str]:
        return list(self.accounts)

    def _pinned(self, service: str | None) -> str:
        """Account a service is pinned to by config, or "" when unpinned.

        Read off the default account because [calendar]/[contacts] are shared
        sections: every account's Config carries the same value.
        """
        attr = _SERVICE_ATTR.get(service or "")
        if not attr:
            return ""
        return getattr(self.accounts[self.default_name], attr, "") or ""

    def get(self, name: str | None = None, service: str | None = None) -> Config:
        """Config for one account.

        `service` ("calendar" or "contacts") picks up [calendar].account /
        [contacts].account when the caller did not name an account, so a Mac
        whose address book lives on a second account stops silently searching an
        empty one. An explicit `name` always wins; it is the caller's override.
        """
        pinned = "" if name else self._pinned(service)
        key = name or pinned or self.default_name
        if key not in self.accounts:
            where = f" (set by [{service}].account)" if pinned else ""
            raise ConfigError(
                f"unknown account '{key}'{where}. "
                f"Configured: {', '.join(self.accounts) or '(none)'}"
            )
        return self.accounts[key]

    def spans_all(self, name: str | None = None, service: str | None = None) -> bool:
        """True when an unpinned read should cover every account.

        Calendar and contacts do not have to live with mail, and when they are
        not pinned the old behaviour was to read the DEFAULT mail account and
        report whatever it found. On a machine where the address book lives
        elsewhere that returns a handful of contacts instead of the whole
        address book, or an empty agenda, with nothing raised and nothing to
        suggest the answer is wrong.

        A config.toml user pins it and that always wins. A user configuring
        through an install form has no way to express the distinction and should
        not have to understand it, so with more than one account and no pin, the
        honest default is to look in all of them. Every result row already
        carries its `account`, so a merged answer stays attributable.

        Mail is deliberately excluded: it always follows the default account.
        """
        if name is not None:
            return False
        return (service in _SERVICE_ATTR
                and not self._pinned(service)
                and len(self.accounts) > 1)

    def fanout(self, name: str | None = None, service: str | None = None) -> list[Config]:
        """Accounts a READ should cover. `name="all"` spans every account."""
        if (name or "").lower() == "all":
            return self.all()
        if self.spans_all(name, service):
            return self.all()
        return [self.get(name, service=service)]

    def require_one(self, name: str | None = None, service: str | None = None) -> Config:
        """Resolve a WRITE to exactly one account. Refuses `name="all"`.

        Fanning a write out would duplicate it on every account, and there is no
        sensible way to undo half of that.
        """
        if (name or "").lower() == "all":
            raise ConfigError(
                "account='all' works for reads only; a write needs one account. "
                f"Pass one of: {', '.join(self.accounts) or '(none)'}."
            )
        return self.get(name, service=service)

    def all(self) -> list[Config]:
        return list(self.accounts.values())


class ConfigError(ValueError):
    pass


_VALID_PRIORITIES = {"high", "normal", "low"}
_VALID_ACTIONS = {"archive", "move", "mark_read", "delete"}


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Load config from `path` (default ~/.config/icloud-mcp/config.toml)."""
    p = Path(os.path.expanduser(str(path or DEFAULT_PATH)))
    if not p.exists():
        raise ConfigError(
            f"config not found at {p}. Copy config.example.toml there and edit it."
        )
    with open(p, "rb") as f:
        data = tomllib.load(f)
    return parse_config(data)


def normalize_apple_address(value: str) -> str:
    """Lowercase and trim an Apple Account address, adding a domain if missing.

    Users type "jane" or "jane@ICLOUD.COM " as readily as the correct form, and
    the distinction between the full address (SMTP, DAV) and the short username
    (IMAP) is our problem to solve, never theirs.
    """
    addr = value.strip().lower().lstrip("<").rstrip(">")
    if "@" not in addr:
        return f"{addr}@{_APPLE_DOMAINS[0]}"
    return addr


def accounts_from_host() -> Accounts | None:
    """Build accounts from MCPB `user_config`, or None if nothing is configured.

    This is the whole config story for an extension install: the user fills in
    the install form and never sees a TOML file. Everything read here goes
    through hostcfg, so an unsubstituted "${user_config.x}" placeholder counts as
    unset rather than as a value.

    Accounts are named by the part before the '@', because with two of them
    "icloud" and "icloud2" would tell a reader nothing, while `status` showing
    `jane` and `jane.work` is self-explanatory. Each gets its OWN trusted-recipient
    store, so approving a recipient on one never authorises a send from the other.

    Two defaults deliberately differ from the TOML path:

    * `send_enabled` is **off**. Someone who installs a mail extension should
      not find it can already send mail, however good the per-recipient gate
      is. They turn it on when they mean it.
    * `style_gate` is **off**. It enforces an opinionated punctuation house style,
      not every user's. Leaving it on would refuse a new user's first reply
      over an em dash they typed on purpose.
    """
    send_enabled = hostcfg.get_bool(ENV_SEND_ENABLED, False)
    service = hostcfg.get_str(ENV_KEYCHAIN_SERVICE) or "icloud-mcp"

    out: dict[str, Config] = {}
    default_name: str | None = None
    for slot in ENV_ADDRESS_SLOTS:
        raw = hostcfg.get_str(slot)
        if not raw:
            continue
        address = normalize_apple_address(raw)
        if "@" not in address or address.startswith("@"):
            continue
        name = address.split("@", 1)[0]
        if name in out:
            # Same short username on two Apple domains (jane@me.com and
            # jane@icloud.com are different accounts). Keep both addressable
            # rather than letting the second silently overwrite the first.
            name = f"{name}2"
            if name in out:
                continue
        out[name] = Config(
            address=address,
            name=name,
            keychain_service=service,
            send_enabled=send_enabled,
            style_gate=False,
            trusted_store=f"~/.local/state/icloud-mcp/trusted_{name}.json",
        )
        if default_name is None:
            default_name = name

    if not out:
        return None
    return Accounts(out, default_name)


def load_accounts(path: str | os.PathLike | None = None) -> Accounts:
    """Load every configured account.

    Resolution order, and the order matters:

    1. `~/.config/icloud-mcp/config.toml` when it exists. A hand-written file always
       wins, so a multi-account setup keeps working after an extension install.
    2. Settings injected by an MCPB host, which is the only path a user ever sees.

    Falling back rather than raising is the difference between an extension that
    installs and works, and one that installs cleanly then fails on every tool call
    with an error about a file the user has never heard of.
    """
    p = Path(os.path.expanduser(str(path or DEFAULT_PATH)))
    if p.exists():
        with open(p, "rb") as f:
            data = tomllib.load(f)
        return parse_accounts(data)

    hosted = accounts_from_host()
    if hosted is not None:
        return hosted

    raise ConfigError(
        "No account configured. If you installed the Claude extension, open "
        "Settings, Extensions, iCloud Mail (Claude Desktop), or run /plugin configure "
        "(Claude Code), and fill in your Apple Account email. "
        f"For a manual install, copy config.example.toml to {p} and edit it."
    )


def parse_accounts(data: dict) -> Accounts:
    """Parse one or many accounts.

    Supports BOTH forms:
      [account]              -> a single account named "default" (legacy, still valid)
      [accounts.<name>]      -> several named accounts

    Shared sections ([scan] [brief] [send] [cleanup] [triage]) apply to every
    account. Per-account keys override: address, keychain_service,
    keychain_account, send_enabled, trusted_store, default.
    """
    blocks = data.get("accounts")
    if not blocks:
        cfg = parse_config(data)          # legacy single-account form
        return Accounts({cfg.name: cfg}, cfg.name)

    if not isinstance(blocks, dict) or not blocks:
        raise ConfigError("[accounts] must contain at least one [accounts.<name>] block")

    out: dict[str, Config] = {}
    default_name: str | None = None
    for name, blk in blocks.items():
        if not isinstance(blk, dict):
            raise ConfigError(f"[accounts.{name}] must be a table")
        cfg = parse_config(data, account_block=blk, account_name=str(name))
        out[cfg.name] = cfg
        if blk.get("default"):
            if default_name is not None:
                raise ConfigError(
                    f"two accounts marked default: '{default_name}' and '{cfg.name}'"
                )
            default_name = cfg.name
    return Accounts(out, default_name or next(iter(out)))


def parse_config(data: dict, account_block: dict | None = None,
                 account_name: str = "default") -> Config:
    """Validate a parsed TOML dict into a Config (separated for easy testing)."""
    account = account_block if account_block is not None else data.get("account", {})
    address = str(account.get("address", "")).strip()
    if not address or "@" not in address:
        where = f"[accounts.{account_name}]" if account_block is not None else "[account]"
        raise ConfigError(f"{where}.address must be a valid email like you@me.com")

    scan = data.get("scan", {})
    brief = data.get("brief", {})
    send = data.get("send", {})
    cleanup = data.get("cleanup", {})
    triage = data.get("triage", {})
    calendar = data.get("calendar", {})
    contacts = data.get("contacts", {})

    window_days = int(scan.get("window_days", 7))
    max_messages = int(scan.get("max_messages", 200))
    if window_days < 1 or max_messages < 1:
        raise ConfigError("[scan] window_days and max_messages must be >= 1")

    brief_hour = int(brief.get("hour", 8))
    brief_minute = int(brief.get("minute", 0))
    if not (0 <= brief_hour <= 23 and 0 <= brief_minute <= 59):
        raise ConfigError("[brief] hour must be 0-23 and minute 0-59")

    triage_rules = []
    for r in triage.get("rules", []):
        pr = str(r.get("priority", "normal")).lower()
        if pr not in _VALID_PRIORITIES:
            raise ConfigError(f"triage rule priority '{pr}' invalid; use high|normal|low")
        if not r.get("match"):
            raise ConfigError("each triage rule needs a 'match' glob")
        triage_rules.append(TriageRule(match=str(r["match"]).lower(), priority=pr))

    cleanup_rules = []
    for r in cleanup.get("rules", []):
        act = str(r.get("action", "")).lower()
        if act not in _VALID_ACTIONS:
            raise ConfigError(f"cleanup rule action '{act}' invalid; use {sorted(_VALID_ACTIONS)}")
        if not r.get("match"):
            raise ConfigError("each cleanup rule needs a 'match' glob")
        if act == "move" and not r.get("folder"):
            raise ConfigError("cleanup rule action 'move' requires a 'folder'")
        cleanup_rules.append(
            CleanupRule(match=str(r["match"]).lower(), action=act, folder=r.get("folder"))
        )

    # Trusted stores must never be shared: one account's approvals must not
    # silently authorise sends from another.
    default_store = "~/.local/state/icloud-mcp/trusted_recipients.json"
    if account_block is not None:
        default_store = f"~/.local/state/icloud-mcp/trusted_{account_name}.json"
    trusted_store = account.get("trusted_store") or send.get("trusted_store") or default_store
    if account_block is not None and not account.get("trusted_store") and send.get("trusted_store"):
        # A shared [send].trusted_store would collide across accounts; namespace it.
        stem = Path(os.path.expanduser(str(send["trusted_store"])))
        trusted_store = str(stem.with_name(f"{stem.stem}_{account_name}{stem.suffix}"))

    return Config(
        address=address,
        name=account_name,
        keychain_service=str(account.get("keychain_service", "icloud-mcp")),
        keychain_account_override=account.get("keychain_account"),
        send_enabled=bool(account.get("send_enabled", True)),
        style_gate=bool(account.get("style_gate", send.get("style_gate", True))),
        window_days=window_days,
        max_messages=max_messages,
        exclude_bulk=bool(scan.get("exclude_bulk", True)),
        brief_hour=brief_hour,
        brief_minute=brief_minute,
        brief_folders=list(brief.get("folders", ["INBOX"])) or ["INBOX"],
        trusted_store=trusted_store,
        allow_delete=bool(cleanup.get("allow_delete", False)),
        protected_senders=[str(s).strip().lower()
                           for s in cleanup.get("protected_senders", []) if str(s).strip()],
        calendar_include=list(account.get("calendar_include", calendar.get("include", []))),
        calendar_write=str(account.get("calendar_write", calendar.get("default_write_calendar", ""))),
        calendar_timezone=str(calendar.get("timezone", "")).strip(),
        calendar_account=str(calendar.get("account", "")),
        contacts_account=str(contacts.get("account", "")),
        triage_rules=triage_rules,
        cleanup_rules=cleanup_rules,
    )
