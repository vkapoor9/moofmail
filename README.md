# Moofmail

Private iCloud Mail, Calendar and Contacts for Claude Code.

Moofmail is a Claude Code plugin that lets Claude read, triage and act on your iCloud
mail, calendar and contacts. It runs on your own computer and talks straight to
Apple's servers over the standard protocols (IMAP, SMTP, CalDAV and CardDAV) using an
app-specific password that you create and can revoke at any time. There is no hosted
service in the middle, no account with us, and no telemetry.

It was built with one rule in mind: Claude may read your mail, but it should not be
able to do something you would not have done yourself. So reading never marks a
message as read, sending is off until you turn it on, Claude has to stop and ask before
anyone new gets an email, deleting only ever moves mail to Trash, and iCloud Notes are
blocked.

> Not affiliated with or endorsed by Apple. iCloud is a trademark of Apple Inc.

*Why the name?* "Moof!" is what Clarus the dogcow says. Clarus was the half-dog, half-cow
pixel animal in the classic Mac OS Page Setup dialog, flipping and shrinking to preview how
your page would print. This project is a small tribute to that kind of Mac care: it quietly
does one job well, on your own machine.

## What you can ask

- "Brief me on my inbox and today's calendar."
- "Anything from a real person I haven't answered this week?"
- "Find the email with the flight confirmation and put the flight on my calendar."
- "Who are my noisiest senders, and what would a cleanup remove?"
- "What's Jane's email address?" and then "Draft a reply to her last message."

## Install

You need:

- **Claude Code** (terminal, IDE extension, or the Code tab in the Claude desktop app).
  The plugin's server runs on your computer, so it does not run in claude.ai chat or
  the mobile apps.
- **uv**, which starts the server and fetches the right Python version by itself:
  `curl -LsSf https://astral.sh/uv/install.sh | sh` (macOS and Linux) or `brew install uv`.
- **An iCloud account with two-factor authentication**, and an app-specific password
  from [account.apple.com](https://account.apple.com) > Sign-In and Security >
  App-Specific Passwords ([Apple's guide](https://support.apple.com/en-us/102654)).

Then, inside Claude Code:

```
/plugin marketplace add vkapoor9/moofmail
/plugin install moofmail@moofmail
```

The install asks for your Apple Account email and the app-specific password. The
password field is masked and, per
[Claude Code's documentation](https://code.claude.com/docs/en/plugins/manifest-reference#user-configuration),
stored in your operating system's secure credential store rather than a settings file. Run `/reload-plugins` (or restart Claude Code) and ask
Claude to "set up iCloud": the bundled **setup** skill checks each step and fixes the
usual problems. To change settings later, run `/plugin configure moofmail@moofmail`.

Tested on macOS and Linux. Windows should work but has not been tested.

Advanced: if `~/.config/icloud-mcp/config.toml` exists, it takes priority over the
plugin settings above (see `config.example.toml`). In that file, sending is controlled
by `send_enabled` per account.

## Settings

| Setting | Default | What it does |
|---|---|---|
| Apple Account email | required | The iCloud address to connect |
| App-specific password | required | Masked, kept in the OS credential store |
| Allow sending email | off | Turns on `send_mail`, `reply_mail` and mailto unsubscribes |
| Second Apple Account | blank | Optional. Useful when calendar or contacts live on another account |

## Tools

**Mail:** `status`, `list_folders`, `list_inbox`, `search_mail`, `get_message`,
`triage_inbox`, `morning_brief`, `draft_reply`, `send_mail`, `reply_mail`,
`reset_trusted_recipients`, `mark_read`, `flag`, `move_message`, `archive`, `trash`

**Cleanup:** `apply_rules`, `find_unsubscribe`, `do_unsubscribe`, `sender_census`,
`cleanup_preview`, `bulk_trash`, `recover_from_trash`

**Calendar:** `list_calendars`, `list_events`, `agenda`, `free_slots`, `create_event`,
`update_event`, `delete_event`

**Contacts:** `search_contacts`, `lookup_contact_email`, `list_contact_groups`

Every tool is annotated as read-only or destructive, so Claude Code can ask before the
ones that change anything.

Skills included: **setup** (guided first run), **daily-brief** (inbox and calendar
summary with suggested actions) and **inbox-cleanup** (a safe, preview-first bulk
cleanup).

## Safety model

- **Reads are invisible.** Messages are fetched with `BODY.PEEK`, so nothing is marked read.
- **Learn-on-approve sending.** Sending is off by default. When on, a message to any
  new address, To or Cc, is refused unless Claude calls again with an explicit
  confirmation, which the skills tell it to do only after you say yes. The tool cannot
  check that you said yes, so the second safeguard is Claude Code's own permission
  prompt: sending tools are marked destructive, so keep them on "ask". After a first
  approved message the address is trusted. Each account keeps its own trusted list.
- **Attachments always need a fresh confirmation**, even to trusted addresses, because
  they read files off your computer.
- **Calendar invitations count as sending.** iCloud emails invitations to attendees,
  so attendees need sending switched on and go through the same approval.
- **Unsubscribing by email counts as sending** and goes through the same approval.
  One-click web unsubscribes do not send mail.
- **Nothing is purged.** Delete means move to Trash, including in cleanup rules. Bulk
  cleanup is preview-first, needs confirmation, re-checks message age at delete time,
  and protects records such as receipts, statements, bookings and security notices.
  People are not detected automatically: list the senders you never want swept as
  `protected_senders` in `config.toml`, and always read the preview.
- **iCloud Notes are blocked.** Apple stores old-style Notes as mail folders; every tool
  refuses them as a source and as a destination, including cleanup rules.
- **Event deletes are guarded.** Calendars have no Trash, so deleting an event shows
  you the whole event first and refuses events that have attendees.
- **Email content is data, not instructions.** The skills tell Claude to ignore
  instructions found inside messages.
- **An audit log** on your computer records every search, every message opened and
  every change or send.

## Phone and voice access (optional)

By itself the plugin works inside Claude Code on this computer. Phone access lets Claude
on your phone, including voice mode, and on claude.ai reach the same mail, calendar and
contacts, still served from your own machine. You need a Mac or Linux machine that stays
on, a free Cloudflare account, and a domain in it (around $10 a year at Cloudflare
Registrar, or a free domain). Nothing is hosted by anyone else.

`moofmail-phone setup` builds a Cloudflare Tunnel (outbound only, no ports opened on your
network) and a Cloudflare Access login in front of it that only your email can pass, with
the sign-in Claude needs. The server checks Cloudflare's signed token again itself, so a
change made in the Cloudflare dashboard cannot widen access on its own. Setup then runs a
self-test and gives you the connector URL only if every check passes: every path refuses
an unauthenticated request, forged tokens are refused at the edge and by the server, the
server listens on 127.0.0.1 only, it serves exactly the tools you chose, the login covers
the whole hostname for exactly one person, and the tunnel token is not visible to other
programs.

Two profiles. **Read** (the default): read mail, calendar and contacts, and add events
without inviting anyone. **Write** (opt in): also organize and trash mail (recoverable),
edit events that have no attendees, and, if you allow sending, send to people you already
approved or have in Contacts; anyone new needs your confirmation. No attachments over the
phone path, and daily caps stop runaway actions. Deleting events, cleanup rules,
unsubscribing by email and resetting approvals are never available there.

The `phone-access` skill walks you through it; ask Claude to "set up phone access". You
type the Cloudflare token and your app-specific password into hidden prompts in your own
terminal. They are never read from environment variables and never pasted into the chat.
The Cloudflare token is used once and not stored; delete it afterwards. Teardown needs a
fresh one: `moofmail-phone token-url` prints the link again, and you add the one
permission Cloudflare's link cannot carry (**Account > Cloudflare Tunnel > Edit**) by hand.
On a server with
Docker, `--platform docker` writes files for the bundled `docker/docker-compose.yml`
instead. `moofmail-phone doctor` re-checks everything without a token (`--with-token` adds the
Access-policy check), `reinstall-services` fixes the
services after a plugin update, and `teardown` removes only what setup created.

## Privacy policy

**What it accesses.** Only the iCloud account or accounts you configure: mail
(read, and, if you allow it, send), calendars and contacts. It never accesses iCloud
Notes, Photos, Drive, or anything else.

**Where data goes.** Directly between your computer and Apple's iCloud servers
(`imap.mail.me.com`, `smtp.mail.me.com`, and Apple's CalDAV and CardDAV hosts) over
TLS. When Claude calls a tool, the result is returned to your Claude Code session, so
it is processed by Anthropic under your Claude account's terms, like anything else
you share in a conversation. The plugin sends nothing to its authors. There is no
analytics or telemetry.

Two other kinds of connection can happen, both started by you:

- **One-click unsubscribe.** When you ask Claude to unsubscribe from a mailing list and
  the message offers a one-click (RFC 8058) link, the plugin sends a single HTTPS POST to
  that sender's own unsubscribe address, which is a third party chosen by the sender. The
  request carries only what the sender put in their link. Nothing from your mailbox is
  added. `find_unsubscribe` shows you the address before anything is sent.
- **First run.** `uv` downloads a Python runtime (from Astral's `python-build-standalone`
  project, if a suitable Python is not already installed) and the plugin's dependencies,
  pinned by `uv.lock`, from the Python Package Index (pypi.org). After that the plugin runs
  from that local copy.
- **Phone and voice access, only if you set it up.** During setup and teardown,
  `moofmail-phone` calls the Cloudflare API (api.cloudflare.com) with the token you type,
  to create or delete the tunnel, DNS record, login rule and Access application in your
  own Cloudflare account. At runtime, requests from Claude on your phone or claude.ai
  reach your machine through Cloudflare's network: Cloudflare Access checks who you are,
  and the tunnel carries the request and the tool's answer. Cloudflare terminates TLS at
  its edge, so mail content in those answers passes through Cloudflare, under your
  Cloudflare account's terms. The background services also fetch Cloudflare's public
  signing keys to verify each request.

**What is stored, and where.** On your own computer only:

- Your app-specific password: in the operating system's secure credential store,
  managed by Claude Code.
- A list of recipients you approved: `~/.local/state/icloud-mcp/trusted_*.json`.
- With phone access: the tunnel token and a second copy of your app-specific password
  in the system keychain (or, on a Linux machine without one, a file only your user can
  read, `~/.config/moofmail/secrets.json`; for Docker, `secrets.env` beside the compose
  file), and `~/.config/moofmail/phone.toml`, which holds no secrets.
- An audit log of actions: `~/.local/state/icloud-mcp/audit.log`. Each line records
  the tool, folder, counts and message numbers, plus search terms, recipient
  addresses and event titles where the action involved them. It never records message
  bodies or credentials.

**Retention.** These files stay until you delete them. Uninstall the plugin with
`/plugin`, delete `~/.local/state/icloud-mcp/`, and revoke the app-specific password
at account.apple.com to remove everything and cut access completely. If you set up phone
access, run `moofmail-phone teardown --yes` first and remove the connector in claude.ai.

**Children.** Not intended for people under 18.

**Contact.** Questions and security reports: open an issue at https://github.com/vkapoor9/moofmail/issues.
Please do not post personal data or credentials in an issue.

## Limits

- Recurring calendar series can be read but not edited; the plugin refuses rather
  than rewrite every occurrence.
- Search is a substring match on the server, so very short words match a lot.
- iCloud only. Gmail and Outlook are not supported.
- Times use your computer's time zone, read from the `TZ` variable or the system
  setting. Where neither is available (some Windows setups) it falls back to UTC;
  set `timezone` in `config.toml` to fix that.

## Development

```
uv run --frozen --extra dev pytest -q
```

The server is plain Python (`icloud_mcp/`), started with `uv run icloud-mcp`.
Configuration can also come from `~/.config/icloud-mcp/config.toml` (see
`config.example.toml`) for multi-account setups with triage and cleanup rules.

## License

MIT. See [LICENSE](LICENSE).
