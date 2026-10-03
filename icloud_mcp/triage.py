"""Triage ranking and morning-brief formatting.

Pure logic over a list of Message objects, no I/O. Score blends: VIP rule
priority, direct-to-me vs bulk, unread, and recency.
"""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from .config import Config
from .models import Message
from .rules import priority_for

_PRIORITY_SCORE = {"high": 100, "normal": 0, "low": -60}


def score_message(msg: Message, cfg: Config, now: datetime | None = None) -> int:
    """Importance score for a single message (higher = more important)."""
    now = now or datetime.now(timezone.utc)
    score = 0

    label = priority_for(msg, cfg.triage_rules)
    if label:
        score += _PRIORITY_SCORE.get(label, 0)

    if msg.is_bulk:
        score -= 40
    else:
        score += 20  # personal/direct mail
        if msg.is_machine_bulk:
            # Platform-sent marketing with no List-Unsubscribe. Demoted, not
            # dropped: the same senders carry login links and receipts.
            score -= 30

    if not msg.seen:
        score += 15  # unread waiting on you

    # recency: up to +24, decaying ~1/day over the window
    if msg.date:
        age_days = max(0.0, (now - msg.date).total_seconds() / 86400.0)
        score += max(0, int(24 - age_days * (24 / max(cfg.window_days, 1))))

    return score


def rank_inbox(messages: list[Message], cfg: Config, now: datetime | None = None) -> list[tuple[Message, int, str]]:
    """Rank messages by score. Returns (msg, score, reason) high-to-low.

    Honors cfg.exclude_bulk (bulk mail dropped unless disabled).
    """
    now = now or datetime.now(timezone.utc)
    rows: list[tuple[Message, int, str]] = []
    for m in messages:
        if cfg.exclude_bulk and m.is_bulk:
            continue
        s = score_message(m, cfg, now)
        rows.append((m, s, _reason(m, cfg)))
    rows.sort(key=lambda r: r[1], reverse=True)
    return rows


def _reason(msg: Message, cfg: Config) -> str:
    bits = []
    label = priority_for(msg, cfg.triage_rules)
    if label == "high":
        bits.append("VIP sender")
    elif label == "low":
        bits.append("low-priority rule")
    if msg.is_machine_bulk:
        bits.append("marketing/platform")
    elif not msg.is_bulk:
        bits.append("direct/personal")
    if not msg.seen:
        bits.append("unread")
    return ", ".join(bits) or "recent"


def _chips(msg: Message, reason: str) -> list[tuple[str, str]]:
    """(label, kind) badges for one item. kind drives the CSS class."""
    out: list[tuple[str, str]] = []
    if "VIP sender" in reason:
        out.append(("VIP", "vip"))
    if not msg.seen:
        out.append(("Unread", "unread"))
    if msg.is_machine_bulk:
        out.append(("Marketing", "mktg"))
    elif "low-priority rule" in reason:
        out.append(("Low", "low"))
    return out


def format_brief_html(
    ranked: list[tuple[Message, int, str]],
    top_n: int = 8,
    now: datetime | None = None,
    events: list | None = None,
    tz=None,
    audit=None,
) -> str:
    """Rich HTML morning brief, styled for Apple Mail (light + dark, phone + desktop).

    Editorial/broadsheet treatment: serif masthead, rule lines, a lead item.
    Everything is inlined - no webfonts, no images, no external requests, since
    mail clients block them. Fonts are macOS/iOS system faces.

    All message-derived text is escaped: subjects and sender names are
    attacker-controlled.
    """
    now = now or datetime.now()
    e = escape
    date_line = now.strftime("%A, %B %-d, %Y") if hasattr(now, "strftime") else ""

    total = len(ranked)
    unread = sum(1 for m, _s, _r in ranked if not m.seen)
    vips = sum(1 for _m, _s, r in ranked if "VIP sender" in r)

    # Schedule block. Every value is escaped: summaries and locations are user data.
    sched_html = ""
    if events:
        rows_s = []
        for ev in events:
            when = ("all day" if ev.all_day else
                    (ev.start.astimezone(tz).strftime("%-I:%M %p")
                     if tz and hasattr(ev.start, "astimezone") else ""))
            loc = f'<span class="evloc">{e(_flat(ev.location))}</span>' if ev.location else ""
            rows_s.append(
                f'<tr><td class="evtime">{e(when)}</td>'
                f'<td class="evbody">{e(_flat(ev.summary))}{loc}</td></tr>'
            )
        sched_html = (
            '<tr><td class="sched">'
            '<div class="schedhead">Today</div>'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
            + "".join(rows_s) + "</table></td></tr>"
        )

    audit_html = _audit_block_html(audit)
    alert = bool(audit is not None and (not audit.ok or audit.alerts))
    audit_top, audit_bottom = (audit_html, "") if alert else ("", audit_html)

    if not ranked:
        body = (
            '<tr><td class="calm">'
            '<div class="calm-mark">&#9788;</div>'
            "<div class='calm-head'>Inbox is calm</div>"
            "<div class='calm-sub'>Nothing needs you right now.</div>"
            "</td></tr>"
        )
    else:
        rows = []
        for i, (m, _score, reason) in enumerate(ranked[:top_n], 1):
            who = e((m.from_name or m.from_addr or "unknown").strip())
            subj = e((m.subject or "(no subject)").strip())
            when = m.date.strftime("%-I:%M %p") if m.date else ""
            lead = " lead" if i == 1 else ""
            chips = "".join(
                f'<span class="chip {kind}">{e(label)}</span>' for label, kind in _chips(m, reason)
            )
            rows.append(
                f'<tr><td class="item{lead}">'
                f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
                f'<td class="num" valign="top">{i}</td>'
                f'<td class="body" valign="top">'
                f'<div class="who">{who}<span class="when">{e(when)}</span></div>'
                f'<div class="subj{lead}">{subj}</div>'
                f'<div class="chips">{chips}</div>'
                f"</td></tr></table></td></tr>"
            )
        if total > top_n:
            rows.append(
                f'<tr><td class="more">and {total - top_n} more waiting in the inbox</td></tr>'
            )
        body = "".join(rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>Morning Brief</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:0; background:#F3EEE4; }}
  /* No width:100% here. With padding and no border-box that overflows the
     viewport by exactly the padding and clips every subject line. */
  .wrap {{ background:#F3EEE4; padding:28px 12px; }}
  .sheet {{ width:100%; max-width:600px; margin:0 auto; background:#FBF8F2;
            border:1px solid #E4DCCD; border-radius:2px; }}
  .masthead {{ padding:34px 34px 18px 34px; text-align:center;
               border-bottom:3px double #D8CDB8; }}
  .kicker {{ font-family:'Avenir Next','Helvetica Neue',Arial,sans-serif;
             font-size:10px; letter-spacing:.24em; text-transform:uppercase;
             color:#A6431C; margin:0 0 10px 0; font-weight:600; }}
  .title {{ font-family:'Iowan Old Style','Palatino Linotype',Palatino,Georgia,serif;
            font-size:38px; line-height:1.05; letter-spacing:-.02em;
            color:#1B1A17; margin:0; font-weight:400; }}
  .dateline {{ font-family:'Iowan Old Style',Palatino,Georgia,serif; font-style:italic;
               font-size:14px; color:#6E6862; margin:10px 0 0 0; }}
  .stats {{ padding:14px 34px; border-bottom:1px solid #E4DCCD;
            font-family:'Avenir Next','Helvetica Neue',Arial,sans-serif;
            font-size:11px; letter-spacing:.14em; text-transform:uppercase;
            color:#6E6862; text-align:center; }}
  .stats b {{ color:#1B1A17; font-weight:600; }}
  .stats .sep {{ color:#CFC4B0; padding:0 8px; }}
  .sched {{ padding:18px 34px 16px 34px; border-bottom:1px solid #E4DCCD;
            background:#F7F2E8; }}
  .schedhead {{ font-family:'Avenir Next','Helvetica Neue',Arial,sans-serif; font-size:10px;
                letter-spacing:.2em; text-transform:uppercase; color:#A6431C;
                font-weight:600; margin:0 0 10px 0; }}
  .evtime {{ width:78px; vertical-align:top; font-family:'Avenir Next',Arial,sans-serif;
             font-size:12px; color:#8A8177; padding:3px 8px 3px 0; white-space:nowrap; }}
  .evbody {{ vertical-align:top; font-family:'Iowan Old Style',Palatino,Georgia,serif;
             font-size:15px; color:#1B1A17; padding:3px 0; overflow-wrap:anywhere; }}
  .evloc {{ display:block; font-family:'Avenir Next',Arial,sans-serif; font-size:11px;
            color:#A99F91; margin-top:1px; }}
  .item {{ padding:20px 34px; border-bottom:1px solid #EDE6D9; }}
  .item.lead {{ background:#FFFDF8; }}
  .num {{ width:38px; font-family:'Iowan Old Style',Palatino,Georgia,serif;
          font-size:26px; line-height:1; color:#C9BCA4; padding-right:8px; }}
  .item.lead .num {{ color:#A6431C; }}
  .who {{ font-family:'Avenir Next','Helvetica Neue',Arial,sans-serif; font-size:12px;
          letter-spacing:.08em; text-transform:uppercase; color:#8A8177; margin:0 0 5px 0;
          overflow-wrap:anywhere; }}
  .when {{ float:right; text-transform:none; letter-spacing:0; color:#B3AA9D; }}
  .subj {{ font-family:'Iowan Old Style','Palatino Linotype',Palatino,Georgia,serif;
           font-size:17px; line-height:1.35; color:#1B1A17; margin:0;
           overflow-wrap:anywhere; }}
  .subj.lead {{ font-size:21px; line-height:1.28; }}
  .chips {{ margin:9px 0 0 0; }}
  .chip {{ display:inline-block; font-family:'Avenir Next','Helvetica Neue',Arial,sans-serif;
           font-size:9px; letter-spacing:.16em; text-transform:uppercase; font-weight:600;
           padding:3px 7px; margin:0 5px 0 0; border-radius:2px;
           background:#EFE8DA; color:#7A7266; }}
  .chip.vip {{ background:#A6431C; color:#FFF6EF; }}
  .chip.unread {{ background:#F2E3D8; color:#A6431C; }}
  .chip.mktg {{ background:#ECE9E2; color:#9A9287; }}
  .more {{ padding:16px 34px; text-align:center;
           font-family:'Iowan Old Style',Palatino,Georgia,serif; font-style:italic;
           font-size:14px; color:#8A8177; border-bottom:1px solid #EDE6D9; }}
  .calm {{ padding:56px 34px; text-align:center; }}
  .calm-mark {{ font-size:34px; color:#C9A227; margin-bottom:12px; }}
  .calm-head {{ font-family:'Iowan Old Style',Palatino,Georgia,serif; font-size:24px;
                color:#1B1A17; }}
  .calm-sub {{ font-family:'Avenir Next',Arial,sans-serif; font-size:13px; color:#8A8177;
               margin-top:6px; }}
  .audit {{ padding:14px 34px; border-bottom:1px solid #EDE6D9;
            font-family:'Avenir Next','Helvetica Neue',Arial,sans-serif;
            font-size:11px; color:#A99F91; text-align:center; }}
  .audit .ahead {{ letter-spacing:.2em; text-transform:uppercase; font-size:9px;
                   font-weight:600; margin:0 0 4px 0; }}
  .audit.alert {{ background:#F9E9DF; color:#7A2E12; text-align:left;
                  border-bottom:2px solid #A6431C; font-size:13px; }}
  .audit.alert .ahead {{ color:#A6431C; }}
  .audit .aitem {{ margin:3px 0 0 0; overflow-wrap:anywhere; }}
  .foot {{ padding:18px 34px 26px 34px; text-align:center;
           font-family:'Avenir Next','Helvetica Neue',Arial,sans-serif;
           font-size:10px; letter-spacing:.1em; color:#A99F91; }}
  @media (prefers-color-scheme: dark) {{
    body, .wrap {{ background:#0E0D0C !important; }}
    .sheet {{ background:#171614 !important; border-color:#2E2B26 !important; }}
    .masthead {{ border-bottom-color:#3A352D !important; }}
    .title {{ color:#EFE9DC !important; }}
    .kicker {{ color:#D97742 !important; }}
    .dateline, .stats {{ color:#9A9287 !important; }}
    .stats {{ border-bottom-color:#2E2B26 !important; }}
    .stats b {{ color:#EFE9DC !important; }}
    .stats .sep {{ color:#4A443B !important; }}
    .sched {{ background:#1A1815 !important; border-bottom-color:#2E2B26 !important; }}
    .schedhead {{ color:#D97742 !important; }}
    .evtime {{ color:#8C8478 !important; }}
    .evbody {{ color:#EFE9DC !important; }}
    .evloc {{ color:#6E675C !important; }}
    .item {{ border-bottom-color:#232019 !important; }}
    .item.lead {{ background:#1C1A17 !important; }}
    .num {{ color:#4A443B !important; }}
    .item.lead .num {{ color:#D97742 !important; }}
    .who {{ color:#8C8478 !important; }}
    .when {{ color:#5E574D !important; }}
    .subj {{ color:#EFE9DC !important; }}
    .chip {{ background:#232019 !important; color:#9A9287 !important; }}
    .chip.vip {{ background:#D97742 !important; color:#17140F !important; }}
    .chip.unread {{ background:#2E211A !important; color:#E8955E !important; }}
    .chip.mktg {{ background:#1F1D19 !important; color:#6E675C !important; }}
    .more, .calm-sub, .foot {{ color:#6E675C !important; }}
    .more {{ border-bottom-color:#232019 !important; }}
    .calm-head {{ color:#EFE9DC !important; }}
    .audit {{ color:#6E675C !important; border-bottom-color:#232019 !important; }}
    .audit.alert {{ background:#2E1A12 !important; color:#F2C4A8 !important;
                    border-bottom-color:#D97742 !important; }}
    .audit.alert .ahead {{ color:#E8955E !important; }}
  }}
  @media only screen and (max-width:480px) {{
    .wrap {{ padding:14px 8px; }}
    .masthead {{ padding:26px 20px 16px 20px; }}
    .title {{ font-size:30px; }}
    .stats {{ padding:12px 16px; font-size:10px; letter-spacing:.1em; }}
    .stats .sep {{ padding:0 5px; }}
    .item, .more, .foot, .audit {{ padding-left:20px; padding-right:20px; }}
    .num {{ width:28px; font-size:20px; padding-right:6px; }}
    .subj {{ font-size:16px; }}
    .subj.lead {{ font-size:19px; }}
    .when {{ float:none; display:block; margin-top:2px; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <table role="presentation" class="sheet" cellpadding="0" cellspacing="0" align="center">
    <tr><td class="masthead">
      <p class="kicker">iCloud MCP</p>
      <h1 class="title">Morning Brief</h1>
      <p class="dateline">{e(date_line)}</p>
    </td></tr>
    <tr><td class="stats">
      <b>{total}</b> items<span class="sep">&bull;</span><b>{unread}</b> unread<span class="sep">&bull;</span><b>{vips}</b> VIP
    </td></tr>
    {audit_top}
    {sched_html}
    {body}
    {audit_bottom}
    <tr><td class="foot">Assembled at {e(now.strftime("%-I:%M %p"))} &nbsp;&middot;&nbsp; read-only</td></tr>
  </table>
</div>
</body>
</html>"""


def _audit_block_html(audit) -> str:
    """The audit-summary row. Everything escaped: addresses come from mail headers."""
    if audit is None:
        return ""
    e = escape
    if not audit.ok:
        return ('<tr><td class="audit alert"><div class="ahead">Security log</div>'
                f'<div class="aitem">Audit log could NOT be read ({e(audit.error)}). '
                "Yesterday's activity is unknown.</div></td></tr>")
    parts = [f"{audit.sends} send{'s' if audit.sends != 1 else ''} "
             f"({len(audit.new_recipients)} to new recipients)",
             f"{audit.remote_calls} remote call{'s' if audit.remote_calls != 1 else ''}"]
    if audit.deletions:
        parts.append(f"{audit.deletions} deletion{'s' if audit.deletions != 1 else ''}")
    summary = " &middot; ".join(e(p) for p in parts)
    if not audit.alerts:
        return ('<tr><td class="audit"><div class="ahead">Last '
                f'{audit.hours} hours</div>{summary} &middot; nothing refused</td></tr>')
    items = "".join(f'<div class="aitem">&#9656; {e(a)}</div>' for a in audit.alerts)
    return ('<tr><td class="audit alert"><div class="ahead">Check this: last '
            f'{audit.hours} hours</div><div>{summary}</div>{items}</td></tr>')


def _flat(v: str) -> str:
    """Collapse whitespace. Locations legitimately contain newlines."""
    return " ".join((v or "").split())


def format_schedule_lines(events: list | None, tz=None) -> list[str]:
    """Plain-text schedule block. Kept ASCII-only: the style gate in scrub.py
    checks text this module authors."""
    if not events:
        return []
    timed = [e for e in events if not e.all_day]
    allday = [e for e in events if e.all_day]
    out = [f"Today ({len(events)} on the calendar):"]
    for e in timed:
        when = e.start.astimezone(tz).strftime("%-I:%M %p") if tz and hasattr(e.start, "astimezone") else ""
        out.append(f"  {when:>9}  {_flat(e.summary)}")
    for e in allday:
        out.append(f"  {'all day':>9}  {_flat(e.summary)}")
    out.append("")
    return out


def format_brief(ranked: list[tuple[Message, int, str]], top_n: int = 8,
                 events: list | None = None, tz=None, audit=None) -> str:
    """Format a compact morning-brief digest (plain text)."""
    sched = format_schedule_lines(events, tz)
    if audit is not None:
        from .auditsum import format_line
        sched = [format_line(audit), ""] + sched
    if not ranked:
        return "\n".join(sched + ["Morning brief: nothing needs you right now. Inbox is calm. ☕"])
    lines = sched + [f"Morning brief: {len(ranked)} items worth a look", ""]
    for i, (m, _score, reason) in enumerate(ranked[:top_n], 1):
        who = m.from_name or m.from_addr
        subj = (m.subject or "(no subject)").strip()
        lines.append(f"{i}. {who}: {subj}  [{reason}]")
    if len(ranked) > top_n:
        lines.append(f"...and {len(ranked) - top_n} more.")
    return "\n".join(lines)
