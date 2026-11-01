---
name: add-pc
description: Install the nethersec Windows PC scanner, a scheduled task that checks Windows Update, Defender, the firewall, winget apps, Node, Go and Java runtimes, WSL distros and CISA's list of exploited flaws, and reports on a change, plus a weekly reminder while a problem stays. Connects it either to a nethersec hub as a direct-message source (a dm= key, no channel, no ping) or straight to a Discord webhook in a private channel. Use when someone says "add my PC", "monitor my Windows laptop", "install the PC scanner", "nethersec on Windows", "send me DMs about PC updates", or a PC's reports stopped arriving.
---

# Add a Windows PC

You end with: the scheduled task `nethersec-pc-security-report` running every 6 hours and 5
minutes after logon, a clean dry run, and one delivery mode with everything it needs.

Reference: `docs/pc/README.md` (every check, delivery, config, tuning, limits).

## Rules

- The scanner only reads. Outside its folder it changes two things: the WSL check runs
  `apt-get update` inside a WSL distro that is already running, which refreshes that distro's
  package lists, and winget refreshes its own source lists (the scanner runs it with
  `--accept-source-agreements`). Say so before the first dry run.
- Never put the key or the webhook URL on a command line, in chat, or in an output you show.
  Never print `config.json`; `last-run.json` is safe to read (it holds no key or URL).
- `-Webhook` asks for the URL with a hidden prompt. The person types it there themselves. If
  your shell cannot answer an interactive prompt, hand that one command to the person.
- A check that cannot read is unknown, not fine. A `CANNOT READ` line needs a reason.
- Work in a normal PowerShell window, not an elevated one.

## 1. Preflight (read-only)

```powershell
node --version                                     # 22 or newer
winget --version                                   # missing: the app checks cannot read
$PSVersionTable.PSVersion                          # Windows PowerShell 5.1 is part of Windows
```

Get the code at a commit you reviewed, then work in its `pc` folder:

```powershell
git clone https://github.com/netherportal3/nethersec.git
cd nethersec\pc
```

## 2. Install

Show what it would do, tell the person, then install:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -WhatIf
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

It copies the scanner to `%USERPROFILE%\.nethersec-pc`, limits that folder to this Windows
account, creates `config.json` and `watch.json` from the examples when missing, and registers
the task (as this user, not elevated, only while logged on, 20-minute limit). It sends nothing
yet.

Several PCs: before step 3, the person sets a different `source` in `config.json` on each
(lowercase letters, digits and dashes, like `laptop`). A key belongs to one source.

## 3a. Through the hub, as direct messages

The person needs their Discord user ID (Developer Mode, right-click their name, Copy User ID).
They must share a server with the bot and allow direct messages from it, or the hub answers 503
and the PC tries again next run.

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -NewKey -HubUrl https://hub.example.com -DiscordUserId 123456789012345678
```

Node makes the key and saves it encrypted in `secret.dpapi`. The key itself is never printed;
the line for the hub is `pc <sha256 of the key> dm=<your Discord user ID>`. On the hub host, in
`hub/`:

```sh
docker compose exec hub node dist/cli.js key add pc <sha256> --dm <your Discord user ID>
```

Use the `source` from `config.json` in place of `pc` if you changed it. A `dm=` key never
pings, never makes a card and cannot send the data events. `hubUrl` must be `https://`, except
to a loopback or private IP address; a private host name over plain http needs
`"allowHttp": true` and sends the key unencrypted across that network.

## 3b. Straight to a Discord webhook (no hub)

The person makes a webhook in a private channel (channel settings, Integrations, Webhooks) and
runs this themselves, pasting the URL into the hidden prompt:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Webhook
```

Only `https://discord.com` (or `ptb`, `canary`, `discordapp.com`) `/api/webhooks/` URLs are
accepted. There is no card state and no Resolve button; each report is one message. Anyone
with the URL can post in that channel: treat it like a password.

## 4. Verify

```powershell
node $env:USERPROFILE\.nethersec-pc\pc-security-report.mjs --dry-run
```

It runs every check, prints one line per event and what it would send, and saves and sends
nothing. Read it:

| Line | Meaning |
|---|---|
| `delivery: ..., ready` | The chosen mode has what it needs. `not ready: <reason>` says what is missing. |
| `ALERT` | Bad now and past its grace window. The `Would send` list shows whether a report goes out this run (one already sent is not sent again until it changes or its weekly reminder is due). |
| `waiting` | Bad, still inside its grace window (`within grace:` says what). |
| `ok` | Read and fine. |
| `CANNOT READ` | Unknown. Fix the reason (winget missing, no network, a bad `watch.json`). |
| `config problem:` | A setting or watch entry is wrong; that part is skipped until fixed. |

`--ignore-grace` shows everything behind regardless of grace (it implies `--dry-run`).

Then one real run through the task, and its summary:

```powershell
Start-ScheduledTask -TaskName nethersec-pc-security-report
Get-Content $env:USERPROFILE\.nethersec-pc\last-run.json
```

Task Scheduler's result code does not tell you how a scan went (the scanner exits 0 even when
it finds problems); `last-run.json` is the truth. Its `reports`
list each send with its result. A healthy PC sends nothing, so silence is expected; delivery is
proven the first time a report goes out and shows a 2xx result there. Only a 2xx counts as
sent; anything else stays pending for the next run.

## 5. Tune (optional)

`watch.json` is the person's own app list (exact winget ids from `winget list`). Grace windows,
reminders and per-check switches are in `config.json`; the table is in `docs/pc/README.md`.
`wsl.startStopped` boots stopped distros, which can start their services and package updates:
only with the person's yes.

## Done when

- [ ] The dry run says `delivery: ..., ready`.
- [ ] No `CANNOT READ` line is left unexplained.
- [ ] Hub mode: `key list` on the hub shows the source with flag `dm`.
- [ ] The person knows a quiet PC sends nothing, and where `last-run.json` is.

## Remove

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
```

It removes the task and keeps the folder (with the key or URL). The person deletes
`%USERPROFILE%\.nethersec-pc` if it is no longer needed, then `key revoke pc` on the hub, or
deletes the webhook in Discord.
