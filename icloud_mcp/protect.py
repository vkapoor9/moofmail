"""What a bulk cleanup must never delete.

Two independent shields, because they fail differently:

* **Senders.** People, not services. People you correspond with often, such as
  colleagues or family, rank high in a volume census precisely because you write
  to them a lot. A naive "delete the top 25 senders" would sweep them up purely
  because they are high-volume.
* **Subjects.** Records that happen to arrive from an otherwise noisy sender.
  An airline's "marketing" stream can be mostly booking confirmations, seat
  assignments and flight cancellations, and noisy retail senders mix in
  purchase confirmations carrying dollar amounts, card statements, and product
  safety recalls.

The lesson for both: **filter before deleting, not after.** Recovering from
Trash works but depends on someone noticing, and nobody notices a missing
booking confirmation until they need it.

Patterns are deliberately narrow. Every widening below was added only after a dry
run showed a real false positive:
  * "code" alone matched "Here is Your 30% Discount Code"
  * "boarding pass" alone matched a retailer's "Here's Your Boarding Pass, 50% Off"
  * "two-factor authentication" alone matched "...enabled for your Apple ID",
    which is a security event worth keeping, not a throwaway code
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------
# Senders that are never bulk-deleted, whatever a scan ranks them at.
#
# **Deliberately EMPTY in code.** The real list is personal to each user (the
# people they correspond with) and belongs in `[cleanup].protected_senders` in
# config.toml, which is never committed. Hardcoding it here would commit private
# addresses to the repo and ship them to every user of the packaged extension.
#
# Kept as a set rather than deleted outright so a future built-in default (say,
# "never delete anything from your own address") has an obvious home.
# --------------------------------------------------------------------------
PROTECTED_SENDERS: set[str] = set()

# --------------------------------------------------------------------------
# Subjects that mark a message as a RECORD rather than noise.
# --------------------------------------------------------------------------
PROTECT: dict[str, list[str]] = {
    "travel": [
        r"booking confirmation", r"itinerar", r"\breservation\b", r"record locator",
        r"\bcheck.?in\b", r"seat assign", r"assigned seats", r"your (?:upcoming )?trip",
        r"upcoming flight", r"flight (?:change|cancel|delay)", r"schedule change",
        r"rebook", r"farelock", r"checked bag",   # "farelock": an airline fare-hold product name
        # Airlines send bare operational notices with no prose at all. "XY83
        # JFK-LAX 03JAN" is the shape of a schedule-change subject that matches none of
        # the wordy patterns above, so match the shape: flight designator plus a
        # three-letter airport pair.
        r"\b[A-Z]{2}\s?\d{1,4}\b.{0,12}\b[A-Z]{3}\s?-\s?[A-Z]{3}\b",
        r"now boarding", r"your flight to",
    ],
    "cancellation": [r"cancellation", r"cancell?ed", r"refund"],
    "safety": [r"\brecall\b", r"safety notice", r"safety alert"],
    "financial": [
        r"\breceipt\b", r"\binvoice\b", r"\bstatement\b", r"purchase is now available",
        r"\btax\b", r"1099", r"proof of payment",
    ],
    "order": [r"return has been", r"\bwarranty\b", r"protection plan", r"\bcoverage\b"],
}

# Subjects that LOOK protected but are marketing. Checked first, and they win.
NOT_PROTECTED: list[str] = [
    r"% off", r"\bsale\b", r"\bdeal(?:s)?\b", r"discount", r"\bcoupon\b", r"\bpromo\b",
    r"tax credit",                 # "Don't Miss the Tax Credit Deadline": marketing, not a tax doc
    r"boarding pass.{0,20}off",    # a retailer's pun
    r"save (?:up to )?\d",
]

# --------------------------------------------------------------------------
# One-time codes. Worthless by construction: they expire in minutes.
# --------------------------------------------------------------------------
OTP: list[str] = [
    r"verification code", r"security code", r"one.?time (?:code|passcode|password|pin)",
    r"\botp\b", r"\bmfa\b", r"two.?factor", r"2fa", r"authentication code",
    r"sign.?in code", r"log.?in code", r"access code", r"confirmation code",
    r"your code is", r"passcode", r"single.use code", r"temporary code",
    r"is your .{0,20}code", r"code to (?:sign|log) in",
]

# Never an OTP even when it matches: security EVENTS, and marketing codes.
NOT_OTP: list[str] = [
    r"password (?:was|has been) changed", r"new device", r"unusual", r"suspicious",
    r"was used to sign in", r"unauthorized", r"breach", r"recovery",
    r"\benabled\b", r"\bdisabled\b", r"bound to", r"turned (?:on|off)",
    r"\bactivated\b", r"has been set up", r"successfully set",
    r"discount code", r"promo(?:tion(?:al)?)? code", r"coupon", r"offer code",
    r"referral code", r"% off",
]

_PROT = {k: [re.compile(p, re.I) for p in v] for k, v in PROTECT.items()}
_NOTPROT = [re.compile(p, re.I) for p in NOT_PROTECTED]
_OTP = [re.compile(p, re.I) for p in OTP]
_NOTOTP = [re.compile(p, re.I) for p in NOT_OTP]


def is_protected_sender(addr: str, extra: set[str] | None = None) -> bool:
    """True if this address is never bulk-deletable."""
    a = (addr or "").strip().lower()
    if not a:
        return False
    return a in PROTECTED_SENDERS or a in {e.lower() for e in (extra or set())}


def protect_reason(subject: str) -> str | None:
    """Category protecting this subject, or None. Marketing wins over records."""
    s = subject or ""
    if any(p.search(s) for p in _NOTPROT):
        return None
    for cat, pats in _PROT.items():
        if any(p.search(s) for p in pats):
            return cat
    return None


def is_otp(subject: str) -> bool:
    """True for a throwaway one-time code. False for security events."""
    s = subject or ""
    if any(p.search(s) for p in _NOTOTP):
        return False
    return any(p.search(s) for p in _OTP)


def deletion_block(addr: str, subject: str, extra_senders: set[str] | None = None) -> str | None:
    """Why this message must not be bulk-deleted, or None if it may be.

    One call for both shields so a caller cannot check one and forget the other.
    OTP messages are explicitly NOT protected: an expired code is never a record,
    even when its subject also matches something like "confirmation code".
    """
    if is_protected_sender(addr, extra_senders):
        return "protected sender"
    if is_otp(subject):
        return None
    cat = protect_reason(subject)
    return f"protected subject ({cat})" if cat else None
