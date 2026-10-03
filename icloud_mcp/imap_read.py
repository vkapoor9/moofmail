"""IMAP read layer for iCloud Mail. READ-ONLY by design.

- Connects over SSL to imap.mail.me.com:993.
- Selects folders read-only and fetches with BODY.PEEK[...] so mail is NEVER
  marked as read by iCloud MCP.
- Lazy single connection, reconnect on drop. Scans are bounded by the config's
  window + max_messages caps to avoid iCloud throttling.

Password is read from Keychain at connect time only (never stored).
"""
from __future__ import annotations

import email
from datetime import datetime, timedelta, timezone
from email.message import Message as EmailMessage

import logging
from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError, CapabilityError

log = logging.getLogger(__name__)

from .config import Config
from .keychain import get_password
from .models import (
    Message, parse_from, parse_date, normalize_headers, decode_mime_header,
)

IMAP_HOST = "imap.mail.me.com"
IMAP_PORT = 993


# iCloud exposes BOTH "Sent Messages" (the real one) and an empty "Sent Items"
# decoy. Order matters: prefer the real one when SPECIAL-USE isn't advertised.
_SENT_FALLBACKS = ("Sent Messages", "Sent", "Sent Items")


def find_sent_folder(client) -> str:
    """Name of the account's Sent folder.

    Prefers the RFC 6154 SPECIAL-USE ``\\Sent`` attribute over guessing by name,
    because iCloud also exposes a "Sent Items" folder that stays empty. Never raises.
    """
    names: list[str] = []
    try:
        for flags, _delim, name in client.list_folders():
            names.append(name)
            for f in flags or ():
                fs = f.decode(errors="replace") if isinstance(f, bytes) else str(f)
                if fs.lower() == "\\sent":
                    return name
    except Exception:  # noqa: BLE001 - a broken LIST must not break sending
        pass
    for cand in _SENT_FALLBACKS:
        if cand in names:
            return cand
    return "Sent Messages"


_TRASH_FALLBACKS = ("Deleted Messages", "Trash", "Deleted Items")


def find_trash_folder(client) -> str:
    """Name of the account's Trash folder.

    iCloud calls it "Deleted Messages" and also exposes a "Deleted Items". Same
    decoy-pair trap as Sent, so prefer the RFC 6154 ``\\Trash`` special-use flag.
    Never raises.
    """
    return _find_special(client, "\\trash", _TRASH_FALLBACKS)


def _find_special(client, flag: str, fallbacks: tuple[str, ...]) -> str:
    names: list[str] = []
    try:
        for flags, _delim, name in client.list_folders():
            names.append(name)
            for f in flags or ():
                fs = f.decode(errors="replace") if isinstance(f, bytes) else str(f)
                if fs.lower() == flag:
                    return name
    except Exception:  # noqa: BLE001 - a broken LIST must not break the operation
        pass
    for cand in fallbacks:
        if cand in names:
            return cand
    return fallbacks[0]


def append_to_sent(cfg: Config, raw: bytes) -> tuple[bool, str]:
    """File a copy of an outgoing message in the Sent folder, flagged as read.

    SMTP alone does not do this; Apple Mail performs the IMAP APPEND itself. Without
    it, mail sent by this server is invisible in Sent on every device.

    Uses its own short-lived connection: MailSender is deliberately isolated from
    the reader's connection. Returns (ok, folder_or_error) and never raises, since
    the mail has ALREADY been delivered by the time this runs.
    """
    client = None
    try:
        pw = get_password(cfg.keychain_account, cfg.keychain_service)
        client = IMAPClient(IMAP_HOST, port=IMAP_PORT, ssl=True, timeout=30)
        client.login(cfg.imap_username, pw)
        folder = find_sent_folder(client)
        client.append(folder, raw, flags=[rb"\Seen"])
        return True, folder
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass


class MailReader:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._client: IMAPClient | None = None

    # ---- connection ----
    def _connect(self) -> IMAPClient:
        pw = get_password(self.cfg.keychain_account, self.cfg.keychain_service)
        client = IMAPClient(IMAP_HOST, port=IMAP_PORT, ssl=True, timeout=30)
        client.login(self.cfg.imap_username, pw)
        return client

    def client(self) -> IMAPClient:
        if self._client is None:
            self._client = self._connect()
        else:
            try:
                self._client.noop()
            except (IMAPClientError, OSError):
                try:
                    self._client.logout()
                except Exception:
                    pass
                self._client = self._connect()
        return self._client

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.logout()
            finally:
                self._client = None

    # ---- reads (always read-only) ----
    def list_folders(self) -> list[str]:
        c = self.client()
        return [name for (_flags, _delim, name) in c.list_folders()]

    def list_inbox(self, folder: str = "INBOX", since_days: int | None = None,
                   limit: int | None = None) -> list[Message]:
        since_days = since_days if since_days is not None else self.cfg.window_days
        limit = limit if limit is not None else self.cfg.max_messages
        c = self.client()
        c.select_folder(folder, readonly=True)
        since = (datetime.now(timezone.utc) - timedelta(days=since_days)).date()
        uids = c.search(["SINCE", since])
        uids = sorted(uids, reverse=True)[:limit]
        return self._fetch_summaries(c, uids)

    def search_mail(self, query: str, folder: str = "INBOX",
                    limit: int | None = None) -> list[Message]:
        limit = limit if limit is not None else self.cfg.max_messages
        c = self.client()
        c.select_folder(folder, readonly=True)
        # search subject OR from OR body for the query text
        crit = ["OR", "OR", "SUBJECT", query, "FROM", query, "TEXT", query]
        uids = c.search(crit)
        uids = sorted(uids, reverse=True)[:limit]
        return self._fetch_summaries(c, uids)

    def get_message(self, uid: int, folder: str = "INBOX") -> Message | None:
        c = self.client()
        c.select_folder(folder, readonly=True)
        resp = c.fetch([uid], ["FLAGS", "INTERNALDATE", "BODY.PEEK[]"])
        if uid not in resp:
            return None
        data = resp[uid]
        raw = data.get(b"BODY[]") or data.get(b"BODY.PEEK[]") or b""
        eml = email.message_from_bytes(raw)
        msg = self._from_email(uid, eml, flags=data.get(b"FLAGS", ()))
        msg.body_text = _extract_text(eml)
        msg.attachments = _attachment_names(eml)
        return msg

    # ---- gated writes (organize) — open folder read-write per op ----
    def mark_read(self, uid: int, folder: str = "INBOX") -> bool:
        c = self.client()
        c.select_folder(folder, readonly=False)
        c.add_flags([uid], [b"\\Seen"])
        return True

    def flag(self, uid: int, folder: str = "INBOX") -> bool:
        c = self.client()
        c.select_folder(folder, readonly=False)
        c.add_flags([uid], [b"\\Flagged"])
        return True

    @staticmethod
    def _move_uids(c: IMAPClient, uids: list[int], dest: str) -> None:
        """Move uids to dest, emulating MOVE when the server lacks it.

        iCloud does NOT advertise the RFC 6851 MOVE capability, so `c.move()`
        raises CapabilityError. The classic equivalent is COPY, flag \\Deleted,
        then EXPUNGE. The copy lands in dest BEFORE anything is expunged, so the
        message is never destroyed - moving to "Deleted Messages" leaves it
        recoverable in Trash exactly as Mail.app does it.
        """
        if not uids:
            return
        try:
            c.move(uids, dest)
            return
        except CapabilityError:
            pass
        c.copy(uids, dest)
        c.add_flags(uids, [rb"\Deleted"])
        try:
            c.expunge(uids)  # UIDPLUS: only these uids
        except Exception:  # noqa: BLE001
            # Never fall back to a bare EXPUNGE: it would also purge anything else
            # in this folder that some other client had flagged \Deleted. The copy
            # is already safe in dest, so the worst case here is a duplicate.
            log.warning("scoped expunge failed; leaving %d flagged message(s) in place",
                        len(uids))

    def move_message(self, uid: int, dest: str, folder: str = "INBOX") -> bool:
        c = self.client()
        c.select_folder(folder, readonly=False)
        if not c.folder_exists(dest):
            c.create_folder(dest)
        self._move_uids(c, [uid], dest)
        return True

    def archive(self, uid: int, folder: str = "INBOX", archive_folder: str = "Archive") -> bool:
        return self.move_message(uid, archive_folder, folder)

    def trash(self, uids: list[int], folder: str = "INBOX") -> tuple[int, str]:
        """Move messages to Trash. Recoverable; emptying Trash is the user's action.

        Split out of move_message so the safest destructive operation does not
        depend on the caller knowing iCloud calls it "Deleted Messages" rather
        than the "Trash" most callers would guess. Resolved by the \\Trash
        special-use flag, mirroring find_sent_folder.
        """
        if not uids:
            return 0, ""
        c = self.client()
        dest = find_trash_folder(c)
        c.select_folder(folder, readonly=False)
        self._move_uids(c, list(uids), dest)
        return len(uids), dest

    # ---- helpers ----
    def _fetch_summaries(self, c: IMAPClient, uids: list[int]) -> list[Message]:
        if not uids:
            return []
        resp = c.fetch(uids, ["FLAGS", "INTERNALDATE", "BODY.PEEK[HEADER]", "RFC822.SIZE"])
        out: list[Message] = []
        for uid in uids:
            data = resp.get(uid)
            if not data:
                continue
            raw = data.get(b"BODY[HEADER]") or data.get(b"BODY.PEEK[HEADER]") or b""
            eml = email.message_from_bytes(raw)
            out.append(self._from_email(uid, eml, flags=data.get(b"FLAGS", ())))
        return out

    @staticmethod
    def _from_email(uid: int, eml: EmailMessage, flags) -> Message:
        headers = normalize_headers(eml.items())
        name, addr = parse_from(eml.get("From", ""))
        flag_strs = tuple(f.decode() if isinstance(f, bytes) else str(f) for f in (flags or ()))
        return Message(
            uid=int(uid),
            from_addr=addr,
            from_name=name,
            to=eml.get("To", ""),
            subject=decode_mime_header(eml.get("Subject", "")),
            date=parse_date(eml.get("Date", "")),
            flags=flag_strs,
            headers=headers,
            snippet="",  # filled from body only on get_message
        )


def _extract_text(eml: EmailMessage, limit: int = 20000) -> str:
    """Best-effort plain-text body extraction."""
    if eml.is_multipart():
        for part in eml.walk():
            if part.get_content_type() == "text/plain" and "attachment" not in str(
                part.get("Content-Disposition", "")
            ):
                return _decode(part)[:limit]
        # fall back to first text/* part
        for part in eml.walk():
            if part.get_content_type().startswith("text/"):
                return _decode(part)[:limit]
        return ""
    return _decode(eml)[:limit]


def _decode(part: EmailMessage) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


def _attachment_names(eml: EmailMessage) -> list[str]:
    names = []
    if eml.is_multipart():
        for part in eml.walk():
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp.lower():
                fn = part.get_filename()
                names.append(fn or "(unnamed attachment)")
    return names
