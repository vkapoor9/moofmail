"""SMTP send layer for iCloud Mail. Isolated + gated.

- Fresh SMTP connection per send (never shares the read connection).
- Learn-on-approve: first send to a NEW recipient must be confirmed by the caller
  (the MCP tool passes confirm=True); once sent, the address is auto-trusted.
- Replies thread via In-Reply-To / References.

Password read from Keychain at send time only.
"""
from __future__ import annotations

import json
import os
import mimetypes
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid, formatdate, getaddresses
from pathlib import Path

from .config import Config
from .imap_read import append_to_sent
from .keychain import get_password
from .scrub import check_outbound, describe

SMTP_HOST = "smtp.mail.me.com"
SMTP_PORT = 587


def clean_header(value: str | None) -> str:
    """Collapse wire folding so a value is safe to assign as a header.

    IMAP hands back long headers (notably References on a deep thread) with their
    CRLF folding intact. EmailMessage refuses any header containing CR or LF, so
    assigning one raw raises ValueError and the send dies before SMTP.
    """
    if not value:
        return ""
    return " ".join(str(value).split())


def reply_recipients(sender: str, to_header: str, cc_header: str, me: str) -> list[str]:
    """Cc list for a reply-all: everyone on the original except me and the sender.

    Threading (In-Reply-To / References) is independent of recipient count, so a
    reply can keep the whole thread AND stay properly nested.
    """
    me_n = (me or "").strip().lower()
    sender_n = (sender or "").strip().lower()
    seen = {me_n, sender_n}
    out: list[str] = []
    for _name, addr in getaddresses([to_header or "", cc_header or ""]):
        a = addr.strip().lower()
        if not a or "@" not in a or a in seen:
            continue
        seen.add(a)
        out.append(a)
    return out


class TrustedStore:
    """Persists auto-approved recipient addresses (learn-on-approve)."""

    def __init__(self, path: Path):
        self.path = path
        self._set: set[str] = set()
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text())
            self._set = {str(a).lower() for a in data.get("trusted", [])}
        except (FileNotFoundError, ValueError):
            self._set = set()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"trusted": sorted(self._set)}, indent=2))

    def is_trusted(self, addr: str) -> bool:
        return addr.lower() in self._set

    def add(self, addr: str) -> None:
        self._set.add(addr.lower())
        self._save()

    def clear(self) -> None:
        self._set = set()
        self._save()


class SendResult:
    def __init__(self, sent: bool, needs_confirmation: bool, detail: str,
                 message_id: str | None = None, filed: bool | None = None,
                 filed_detail: str | None = None,
                 newly_trusted: list[str] | None = None):
        self.sent = sent
        self.needs_confirmation = needs_confirmation
        self.detail = detail
        self.message_id = message_id
        # filed: copy written to the Sent folder. None when no send was attempted.
        self.filed = filed
        self.filed_detail = filed_detail
        # Addresses this send added to the trusted store. The audit log records
        # them, because granting trust is the one event a brief must surface.
        self.newly_trusted = newly_trusted or []

    def as_dict(self) -> dict:
        return {
            "sent": self.sent,
            "needs_confirmation": self.needs_confirmation,
            "detail": self.detail,
            "message_id": self.message_id,
            "filed_to_sent": self.filed,
            "filed_detail": self.filed_detail,
            "newly_trusted": self.newly_trusted,
        }


class MailSender:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.trusted = TrustedStore(cfg.trusted_store_path)

    def send(self, to: str, subject: str, body: str, *, confirm: bool = False,
             in_reply_to: str | None = None, references: str | None = None,
             html: str | None = None, cc: list[str] | None = None,
             attachments: list[str] | None = None, allow_style: bool = False) -> SendResult:
        """Send mail with learn-on-approve gating.

        If `to` is a new recipient and confirm is not True, returns a
        needs_confirmation result WITHOUT sending. Once sent, `to` is auto-trusted.

        `html`, when given, is sent as a multipart/alternative richer part with
        `body` kept as the plain-text fallback.
        """
        if not self.cfg.send_enabled:
            return SendResult(
                False, False,
                f"sending is disabled for account '{self.cfg.name}' "
                f"({self.cfg.address}). Turn on 'Allow sending email' in the plugin "
                f"settings, or set send_enabled = true in config.toml.",
            )

        # Optional style gate: blocks characters that read as machine-written.
        # Enforced in code so it does not depend on the model remembering.
        style = check_outbound(subject, body)
        if self.cfg.style_gate and not style["ok"] and not allow_style:
            return SendResult(
                False, False,
                f"blocked by style rule: {describe(style)}. "
                "Rewrite, or re-call with allow_style=True if the text is quoted.",
            )

        # getaddresses, never a split(","), because a display name may legally
        # contain a comma ("Doe, Jane <j@example.com>") and splitting would invent
        # two broken recipients out of one good one.
        to_list = [a.strip().lower()
                   for _n, a in getaddresses([to or ""]) if a and a.strip()]
        if not to_list or any("@" not in a for a in to_list):
            return SendResult(False, False, f"invalid recipient: {to!r}")

        cc_list = [c.strip() for c in (cc or []) if c and c.strip()]
        # The gate covers EVERY recipient, ONE ADDRESS AT A TIME. A trusted To must
        # never smuggle an untrusted Cc out of the building, and a multi-address To
        # must never be gated as one opaque string. Gated that way, the composite
        # matches nothing in the store, and confirm=True then trusts that whole
        # string as if it were an address. The per-recipient check would quietly
        # stop meaning anything the moment a second address appeared in To.
        all_norm = to_list + [c.lower() for c in cc_list]
        new = [a for a in all_norm if not self.trusted.is_trusted(a)]
        if new and not confirm:
            who = ", ".join(f"'{a}'" for a in new)
            if len(new) > 1:
                detail = (f"{who} are new recipients. "
                          "Re-call with confirm=True to send and trust them.")
            else:
                detail = (f"{who} is a new recipient. "
                          "Re-call with confirm=True to send and trust it.")
            return SendResult(False, True, detail)

        msg = EmailMessage()
        msg["From"] = self.cfg.address
        msg["To"] = to
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)
        msg["Subject"] = clean_header(subject)
        msg["Date"] = formatdate(localtime=True)
        msg_id = make_msgid()
        msg["Message-ID"] = msg_id
        if in_reply_to:
            # clean_header: IMAP returns these still folded across lines, and a header
            # value containing CR/LF raises ValueError.
            irt = clean_header(in_reply_to)
            refs = clean_header(references)
            msg["In-Reply-To"] = irt
            msg["References"] = f"{refs} {irt}".strip() if refs else irt
        msg.set_content(body)
        if html:
            # multipart/alternative: plain-text stays the fallback for clients
            # that refuse HTML, and for accessibility.
            msg.add_alternative(html, subtype="html")

        for path in (attachments or []):
            p = Path(path).expanduser()
            if not p.is_file():
                return SendResult(False, False, f"attachment not found: {p}")
            ctype, _enc = mimetypes.guess_type(p.name)
            maintype, _, subtype = (ctype or "application/octet-stream").partition("/")
            msg.add_attachment(p.read_bytes(), maintype=maintype,
                               subtype=subtype or "octet-stream", filename=p.name)

        # Attachments read files off this computer, so a message that carries any
        # needs an explicit confirm even to a trusted recipient. Otherwise text
        # injected into an email could ask for a private file to be mailed to an
        # address that was trusted for an unrelated reason.
        if attachments and not confirm:
            names = ", ".join(os.path.basename(a) for a in attachments)
            return SendResult(False, True,
                              f"this message attaches files from your computer ({names}). "
                              "Re-call with confirm=True once the user has agreed.")

        pw = get_password(self.cfg.keychain_account, self.cfg.keychain_service)
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login(self.cfg.address, pw)  # SMTP username = full address
            # send_message RETURNS partially-refused recipients instead of raising
            # (it only raises when every recipient is refused). Swallowing that
            # makes a partial failure look exactly like a clean send.
            refused = s.send_message(msg) or {}

        delivered = [a for a in all_norm if a not in {k.lower() for k in refused}]
        newly = [a for a in delivered if a in new]
        for a in delivered:
            self.trusted.add(a)  # only trust addresses the server actually took

        # File a copy in Sent. The mail is already delivered, so a failure here is
        # reported but must NEVER turn a successful send into a failed one.
        filed_ok, filed_where = append_to_sent(self.cfg, msg.as_bytes())

        where = to if not cc_list else f"{to} (cc {', '.join(cc_list)})"
        if refused:
            bad = ", ".join(f"{k} ({v[0]} {v[1].decode(errors='replace') if isinstance(v[1], bytes) else v[1]})"
                            for k, v in refused.items())
            return SendResult(True, False,
                              f"PARTIAL: sent to {where}, but REFUSED: {bad}",
                              message_id=msg_id, filed=filed_ok, filed_detail=filed_where,
                              newly_trusted=newly)
        return SendResult(True, False, f"sent to {where}", message_id=msg_id,
                          filed=filed_ok, filed_detail=filed_where, newly_trusted=newly)
