"""Unsubscribe: parse List-Unsubscribe headers and execute standardized one-click.

Parsing is pure/testable. Execution does a network POST (RFC 8058) or a mailto
send, and is kept separate so the decision logic can be tested without network.

v1 does standardized one-click ONLY. Senders that offer only a webpage link are
returned for a manual tap, never auto-clicked (no browser automation).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import Message

_ANGLE = re.compile(r"<([^>]+)>")


@dataclass
class UnsubPlan:
    method: str            # "one-click" | "mailto" | "manual" | "none"
    target: str | None     # https URL, mailto address, or manual URL
    reason: str


def parse_unsubscribe(msg: Message) -> UnsubPlan:
    """Decide how (if at all) to unsubscribe from this message.

    RFC 8058 one-click requires BOTH:
      - a List-Unsubscribe header with an https URL, and
      - a List-Unsubscribe-Post: List-Unsubscribe=One-Click header.
    Without the -Post header we fall back to a mailto (if present) or flag manual.
    """
    h = msg.headers
    raw = h.get("list-unsubscribe")
    if not raw:
        return UnsubPlan("none", None, "no List-Unsubscribe header")

    targets = _ANGLE.findall(raw)
    if not targets:  # some senders omit the angle brackets
        targets = [t.strip() for t in raw.split(",") if t.strip()]

    https = next((t for t in targets if t.lower().startswith("https://")), None)
    mailto = next((t for t in targets if t.lower().startswith("mailto:")), None)

    post = h.get("list-unsubscribe-post", "").lower().replace(" ", "")
    one_click = post == "list-unsubscribe=one-click"

    if https and one_click:
        return UnsubPlan("one-click", https, "RFC 8058 one-click POST")
    if mailto:
        return UnsubPlan("mailto", mailto[len("mailto:"):].split("?")[0], "mailto unsubscribe")
    if https:
        return UnsubPlan("manual", https, "https link present but not one-click; needs a manual tap")
    return UnsubPlan("none", None, "no actionable unsubscribe target")


def execute_one_click(url: str, timeout: float = 15.0) -> tuple[bool, str]:
    """Fire the RFC 8058 one-click POST. Returns (ok, detail).

    Network side effect, not exercised by unit tests. HTTPS only (never plain http).
    """
    import urllib.request
    import urllib.error

    if urlparse(url).scheme != "https":
        return False, f"refusing non-https unsubscribe URL: {url}"
    data = b"List-Unsubscribe=One-Click"
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            return (200 <= code < 400), f"HTTP {code}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 - report any network failure to the caller
        return False, f"{type(e).__name__}: {e}"
