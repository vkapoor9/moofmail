---
name: phone-access
description: Set up, check or remove phone and voice access for Moofmail, so Claude on a phone (including voice mode) or on claude.ai can read iCloud mail, calendar and contacts served from the user's own Mac or Linux machine. Use when someone asks "use my mail from my phone", "voice mode with my iCloud", "set up the remote connector", "phone access", "it stopped working on my phone", or wants to remove it. Walks through the manual Cloudflare steps, then runs moofmail-phone.
---

# Phone and voice access

The plugin itself only runs inside Claude Code on this computer. Phone access adds a
second, separate piece: a small server on the user's own always-on machine, reached
through a Cloudflare Tunnel in the user's OWN Cloudflare account, behind a login only
they can pass. Nobody else hosts anything, and the mail never leaves their machine
except to answer their own Claude.

## Rules for you (Claude)

- **Never ask for the Cloudflare API token or the Apple app-specific password in chat.**
  The user runs setup in their own terminal, where both are typed into hidden prompts.
  If they paste one into the conversation anyway, tell them to delete that token or
  password and make a new one.
- Run only `token-url`, `doctor` (after the user has the token ready in their own
  terminal) and `reinstall-services` yourself. `setup` and `teardown --yes` are the
  user's to run.
- Before setup, say plainly what the choices mean (below). Do not pick the write profile
  for them.

## What the user needs first

1. **A machine that stays on**: a Mac or a Linux machine (a home server or a VPS). If it
   sleeps, Claude on the phone cannot reach the mail.
2. **A Cloudflare account** with two-factor sign-in turned on (free).
3. **A domain in that account.** Easiest: buy one at Cloudflare Registrar (around $10 a
   year at cost; it is set up automatically). Free domains such as EU.org also work, with
   one risk to state: whoever runs the parent domain can revoke or reassign the name.
   That cannot open the mailbox, but a reassigned name could point their Claude at a
   fake connector.
4. **Zero Trust switched on**: Cloudflare dashboard > Zero Trust. Choose a team name
   once and make it general (it becomes the login page for everything they protect;
   renaming it later breaks existing apps). Pick the Free plan; Cloudflare asks for a
   card even on Free and does not charge it.
5. **cloudflared installed**: `brew install cloudflared` on a Mac, or the distribution's
   package on Linux. Not needed for the Docker route.

Disclose these before they start:

- **On a VPS**, the hosting provider has root on the machine that holds the Apple
  password.
- **On a Mac with FileVault on**, a reboot needs someone to log in before mail works
  again. With it off, it recovers alone but the disk is not encrypted. Their call.

## The token

Show the user the token link (this prints it; safe to run yourself):

```
uv run --frozen --quiet --project "${CLAUDE_PLUGIN_ROOT}" moofmail-phone token-url
```

The link pre-fills five permissions. Cloudflare's link format has no key for tunnels, so
they add one line by hand: **Account > Cloudflare Tunnel > Edit**. Setup checks every
permission first and names any that is missing.

## Setup (the user runs this in their own terminal)

Give them this command with their two email addresses filled in. Use a separate Terminal
window, not this chat, so the hidden prompts work:

```
uv run --frozen --quiet --project "${CLAUDE_PLUGIN_ROOT}" moofmail-phone setup \
  --email THE-ADDRESS-THEY-WILL-SIGN-IN-WITH --apple-id THEIR-APPLE-ACCOUNT-EMAIL
```

Options to explain:

- `--profile read` (default): Claude on the phone can read mail, calendar and contacts
  and add calendar events without inviting anyone. Nothing else.
- `--profile write` adds organizing mail, moving it to Trash (recoverable), editing events
  that have no attendees, and with `--allow-send` sending and replying: people already
  approved or in Contacts go straight out, anyone new needs confirmation. No attachments,
  and daily caps apply. The model that reads strangers' mail is the one that would send,
  so suggest read first.
- `--domain` and `--hostname` if they have several domains (default `mail.<domain>`).
- `--platform docker` on a server that runs Docker; it writes `phone.toml` and
  `secrets.env` for the bundled `docker/docker-compose.yml` instead of installing services.

Setup creates everything, starts two background services, and runs a seven-part
self-test. It prints the connector URL only if every check passes. If setup stops
halfway, `teardown --yes` removes what it made.

## After setup

1. In claude.ai: **Customize > Connectors > Add custom connector**, paste the URL, choose
   **Sign in now** and **Register automatically**, then sign in. With the emailed code:
   request it once, do not tap the link in the email, type the newest code by hand.
2. **Delete the Cloudflare token** (My Profile > API Tokens). Setup did not keep it.
3. A sign-in lasts about a year. Offer to add two reminders to their calendar, a week
   before and on the day, but only with their OK.

## Checking and fixing

- **Something stopped working:** `moofmail-phone doctor` (no token needed; `--with-token`
  also checks the Access policy, with a fresh token) re-runs the self-test, notes how long the sign-in has left, and spots a renamed team.
- **After a plugin update:** `moofmail-phone reinstall-services` points the services at
  the new version. No token needed.
- **Removing it:** needs a fresh token made the same way as the first (`token-url`, plus
  the Tunnel line by hand). `moofmail-phone teardown` shows what it would delete, `--yes`
  deletes only what setup created, then they remove the connector in claude.ai and
  delete that token too.

Prefix each command with `uv run --frozen --quiet --project "${CLAUDE_PLUGIN_ROOT}"`.
