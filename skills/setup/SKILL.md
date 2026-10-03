---
name: setup
description: Guided first-time setup for Moofmail, the iCloud Mail, Calendar and Contacts plugin. Use when someone has just installed the plugin, says "set up iCloud", "connect my iCloud mail", "it says no account configured", "the iCloud tools are missing", or asks how to get an app-specific password. Walks through each step, checks it worked, and fixes the common failures.
---

# Set up Moofmail

You are walking a person, who may not be technical, through connecting their iCloud
account. Go one step at a time. After each step, check that it worked before moving
on. Never ask them to paste their Apple Account password or their app-specific
password into the chat, and if they do paste one, tell them to revoke it at
account.apple.com and make a new one.

The plugin's tools only run in **Claude Code** (the terminal, the IDE extensions, or
the Code tab in the Claude desktop app). If they are in regular chat on claude.ai or
the phone, explain that and stop.

## Step 1: check whether it already works

Call the plugin's `status` tool.

- If it answers with an account and `serves`, setup is done. Jump to Step 6.
- If the tool does not exist, go to Step 2.
- If it errors with "No account configured" or "No app-specific password", go to Step 4.

## Step 2: make sure `uv` is installed

The server is written in Python and is started by `uv`, which also downloads the
right Python version on its own. Run `uv --version`.

If it is missing, offer to install it and run the command once they agree:

- macOS or Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- macOS with Homebrew: `brew install uv`
- Windows (PowerShell): `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`

Then ask them to fully quit and reopen Claude Code so it picks up the new command.

## Step 3: confirm two-factor authentication

App-specific passwords need two-factor authentication on the Apple Account. Almost
every modern account has it. If the menu in Step 4 is missing, that is why: they
need to turn two-factor authentication on first. Apple's own page on app-specific
passwords explains it: https://support.apple.com/en-us/102654

## Step 4: create an app-specific password

Ask them to do this themselves, in their browser:

1. Go to https://account.apple.com and sign in.
2. Open **Sign-In and Security**, then **App-Specific Passwords**.
3. Click **Generate an app-specific password**, name it something like "Claude".
4. Copy the password it shows. It looks like `abcd-efgh-ijkl-mnop`. Apple shows it once.

Tell them plainly: this password can only reach mail, calendar and contacts, and it
can be revoked at any time from the same page without touching their main password.
Changing their main Apple Account password revokes every app-specific password, so
after a password change they need a new one.

## Step 5: enter it into the plugin, not the chat

Have them run this command in Claude Code and fill in the form:

```
/plugin configure moofmail@moofmail
```

(If they installed from Anthropic's directory and that name is not found, `/plugin`
opens the plugin manager, where the plugin's configure option shows the same form.)

The form asks for the Apple Account email and the app-specific password. The password
field is masked and stored in the operating system's secure credential store. Leave
**Allow sending email** off for now; they can turn it on later from the same form.

Then run `/reload-plugins`, or restart Claude Code, and go back to Step 1.

## Step 6: prove it with their own data

Run these and show short results, so they can see it is their account:

1. `status`: which address is connected and whether sending is on.
2. `list_folders`: their mail folders.
3. `agenda`: today's calendar.
4. `search_contacts` with a name they choose.

If folders appear but calendar or contacts are empty when they expected data, check
`status` first. Calendar and contacts may live on a different Apple Account than mail.
If so, add that account as the second account in the same configure form.

## Step 7: explain the safety rules in two sentences

Reading never marks mail as read, and iCloud Notes are blocked. Sending is off until
they switch it on; even then you must ask them before the first message to anyone new
and before any attachment, and only then re-call with confirm=True. Deleting only ever
moves mail to Trash. Suggest they keep Claude Code's permission prompt on "ask" for
the sending and deleting tools, so they see each one before it runs.

## Common failures

| Symptom | Cause and fix |
|---|---|
| `uv: command not found` in the server log | Step 2, then fully restart Claude Code |
| "authentication failed" | Wrong or revoked app-specific password, or the main Apple password was changed. Make a new one (Step 4) and re-run Step 5 |
| Tools missing after configuring | Run `/reload-plugins` or restart Claude Code; check `/mcp` for the server's error |
| Contacts or calendar empty | They live on another Apple Account. Add it as the second account |
| Asked to use a Notes folder | Blocked on purpose. Notes are never read |
