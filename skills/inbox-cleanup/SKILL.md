---
name: inbox-cleanup
description: Clean up a large iCloud mailbox by volume, safely. Use when the user wants to reduce inbox size, find the senders flooding their inbox, unsubscribe from marketing, delete old bulk mail, or asks "what's filling up my inbox", "clean up my email", "who sends me the most", "let's do another round of cleanup". Covers the sender census, the unsubscribe pass, bulk trashing with guards, and recovery when something is swept up by mistake.
---

# Inbox cleanup

Reduce a large mailbox without losing anything that matters. A naive sweep by
volume can move thousands of messages and then have to give hundreds back.

**The safety rules are enforced in code, not here.** `icloud_mcp/protect.py` and
`icloud_mcp/cleanup.py` block protected senders and record-type subjects, hold the
age guard, and refuse to purge. Do not re-implement any of that in a script; call
the tools. What this skill carries is the sequence and the judgement that cannot
be coded.

## The one thing to understand first

**Ranking senders by volume surfaces the people you care about most.** People
you correspond with often, such as colleagues or family, rank high in a volume
census precisely because you write to them. The top senders by volume also tend
to include airline booking confirmations, purchase records carrying dollar
amounts, card statements, and product safety recalls from retailers.

Volume tells you where the noise is. It does not tell you what is disposable.

## Workflow

### 1. Census

```
sender_census(window_days=730, protect_days=90, limit=25, account="all")
```

Read-only. Each sender splits four ways: `total`, `deletable`, `blocked` (a
protected person or a record) and `protected_by_age` (inside the guard).

**A high `blocked` count is a signal, not noise.** It means that sender mixes
records into its stream. An airline that comes back with most of its mail
`blocked` and nothing `deletable` is the tool saying "this is not the marketing
you think it is."

### 2. Present a table and get a decision

Show the user total / deletable / blocked per sender. Do not act on the census
alone.

Before recommending anything, **sample the subjects**. Senders mix marketing and
transactional mail on the same address. A card issuer sends both statements and
travel booking confirmations. A large retailer mixes shipping noise with product
recalls.

### 3. Unsubscribe before deleting

Deleting old mail without unsubscribing means it comes straight back.

```
find_unsubscribe(uid=...)     # reports the mechanism, does NOT judge
do_unsubscribe(uid=...)
```

Judgement the tool cannot make:

- **Lookalike domains.** `brand-alerts.example` is not `brand.example`.
  Unsubscribing confirms the address is live and raises its value on broker
  lists. Use a rule or a block instead.
- **Check the link for the recipient address**, sometimes reversed or encoded.
  `moc.duolci=elpmaxe` is `example@icloud.com` backwards. That is a list-broker
  fingerprint.
- **one-click (HTTPS POST) is safe. mailto sends mail from the user's account**,
  so it trips the send gate and needs their approval like any other send.
- **`202` means queued, not done.** Expect days. `200` means processed.
- A sender can advertise RFC 8058 and then `403` the POST. If that happens, open
  the link in a browser rather than giving up.

### 4. Preview

```
cleanup_preview(senders=[...], window_days=730, protect_days=90, account="all")
```

Changes nothing. Returns `would_trash`, `would_block`, and sample subjects for
both. **Read `block_samples` out loud to the user.** That is the step that
catches "this sender is 80% booking confirmations" before anything moves.

### 5. Trash

```
bulk_trash(senders=[...], confirm=True, account="all")
```

Recoverable, never purged. The plan is rebuilt and every message re-dated
immediately before the move; the run aborts entirely rather than half-deleting if
anything drifted inside the guard.

`account=None` means the default account only. Pass `account="all"` deliberately.

### 6. Verify against a known number

**Never report success from the tool's own return value.** Compare a live count to
something independently true:

- messages remaining from a swept sender should equal its `protected_by_age`
- Trash should have grown by the number moved
- protected senders should still show `deletable: 0`

This is the check that catches real bugs; a tool's own success message cannot.

## Recovery

```
recover_from_trash(records_only=True, confirm=True, account="all")
```

`records_only=True` selects exactly what the protection rules would have shielded.
It is how to undo a sweep that ran before those rules existed, or one that used a
wider net than intended.

## One-time codes

2FA / OTP / MFA codes expire in minutes, so age is irrelevant and they are always
disposable. `protect.py` deliberately does NOT protect them even when the subject
contains a word like "confirmation code".

Two things it does protect, and they look similar:

- **security events**: "Two-factor authentication enabled for your Apple ID" is a
  record that 2FA was turned on, worth keeping.
- **marketing codes**: "Here is Your 30% Discount Code" is not security at all.

## Adding a protected sender

Never hardcode. Add it to `[cleanup].protected_senders` in
`~/.config/icloud-mcp/config.toml`, which is local to the machine and never
committed, so personal addresses never reach a repo or a shipped build.

## Hard rules

- **Delete means move to Trash.** Emptying it is the user's action, never yours.
- **Nothing inside `protect_days` is ever touched.** Default 90.
- **Show the table and get explicit approval before any `confirm=True` call.**
- If the user names exceptions ("all except X"), and something else in the list
  is a person rather than a service, **hold it and ask.** Excluding one person by
  name does not mean every other person in the list was meant to go.
