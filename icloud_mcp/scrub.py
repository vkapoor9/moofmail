"""Deterministic style gate for anything this server sends.

An optional outbound style gate: blocks characters that read as machine-written
(em dashes, curly quotes, the ellipsis character). Banned characters are the
unambiguous part, so they are enforced here in code instead of depending on the
model remembering.

The character and phrase lists below are an example house style; edit to taste.
The gate is off by default for host (extension) installs.

HARD violations block a send. SOFT ones are reported but never block, because they
need judgement (a quoted reply legitimately carries the other person's phrasing).
"""
from __future__ import annotations

import re

# Unambiguous. There is always a plain-ASCII alternative.
HARD_CHARS: dict[str, str] = {
    "—": "em dash -> period, comma, semicolon, or two sentences",
    "–": "en dash -> 'to' or a hyphen",
    "…": "ellipsis character -> three periods ...",
    "“": 'curly double quote -> straight "',
    "”": 'curly double quote -> straight "',
    "‘": "curly apostrophe -> straight '",
    "’": "curly apostrophe -> straight '",
    " ": "non-breaking space -> a regular space",
}

_SOFT = [
    "let's dive in", "dive into", "in today's", "it's worth noting", "leverage",
    "utilize", "seamless", "robust", "delve", "navigate the complexities", "unlock",
    "elevate", "empower", "harness", "synergy", "holistic", "cutting-edge",
    "game-changer", "revolutionize", "furthermore", "moreover", "in conclusion",
    "feel free to", "don't hesitate", "i hope this helps", "happy to assist",
    "i'd love to help", "let me know if you have any questions",
]
_SOFT_RE = re.compile("|".join(re.escape(s) for s in _SOFT), re.I)

# Words that can carry contractual weight in business mail. Part of the example
# house style. Reported, never blocking: they are legitimate in ordinary
# correspondence ("the warranty on the laptop").
_CAUTION_RE = re.compile(
    r"\b(warrant(?:y|ies|ed|s)|guarantee[sd]?|guaranteeing|insure[sd]?|insuring)\b", re.I
)


def scan(text: str | None) -> dict:
    """Return {'hard': [...], 'soft': [...], 'caution': [...]} for one blob of text."""
    t = text or ""
    hard = []
    for ch, advice in HARD_CHARS.items():
        n = t.count(ch)
        if n:
            hard.append({"char": ch, "count": n, "fix": advice})
    soft = sorted({m.group(0).lower() for m in _SOFT_RE.finditer(t)})
    caution = sorted({m.group(0).lower() for m in _CAUTION_RE.finditer(t)})
    return {"hard": hard, "soft": soft, "caution": caution}


def check_outbound(subject: str | None, body: str | None) -> dict:
    """Scan an outgoing subject + body together. `ok` is False only for HARD hits."""
    s, b = scan(subject), scan(body)
    hard = s["hard"] + b["hard"]
    return {
        "ok": not hard,
        "hard": hard,
        "soft": sorted(set(s["soft"] + b["soft"])),
        "caution": sorted(set(s["caution"] + b["caution"])),
    }


def describe(result: dict) -> str:
    """One-line human summary of a check_outbound result."""
    bits = []
    for h in result["hard"]:
        bits.append(f"{h['count']}x {h['fix']}")
    return "; ".join(bits)


def autofix(text: str | None) -> str:
    """Fix ONLY the mechanical substitutions, never the ones needing judgement.

    Curly quotes, the ellipsis character and non-breaking spaces have exact ASCII
    equivalents. Dashes deliberately are NOT auto-fixed: the right replacement is a
    period, comma or a rewrite depending on the sentence, and silently guessing
    would change text the user already approved.
    """
    t = text or ""
    for a, b in (("“", '"'), ("”", '"'), ("‘", "'"), ("’", "'"),
                 ("…", "..."), (" ", " ")):
        t = t.replace(a, b)
    return t
