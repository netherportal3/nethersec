# nethersec PC scanner

A Windows scheduled task that checks this PC for missing security fixes and protection that
was turned off (Windows Update, Defender, the firewall, winget apps, Node/Go/Java, WSL, and
CISA's list of exploited flaws). It reports when something changes, plus a weekly reminder
while a problem stays, to a nethersec hub (as a Discord direct message) or straight to a
Discord webhook. It only reads; it never installs, upgrades or removes anything. (The WSL check
does refresh a running distro's package lists.)

The full guide is `docs/pc/README.md` in the nethersec repo: every check, what it reads,
delivery, config, tuning and limits.

## Quick start

From this folder, in a normal (not elevated) PowerShell window, with Node.js 22 or newer on PATH:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -WhatIf   # shows what it would do
powershell -ExecutionPolicy Bypass -File .\install.ps1 -NewKey -HubUrl https://hub.example.com -DiscordUserId 123456789012345678
#   or, without a hub:
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Webhook
node $env:USERPROFILE\.nethersec-pc\pc-security-report.mjs --dry-run
```

`-NewKey` prints one line for the hub's keys file (source, SHA-256 of the key, `dm=` flag); the
key itself is never printed. `-Webhook` asks for a Discord webhook URL without showing it.
Either one is stored in `secret.dpapi`, encrypted with Windows DPAPI for your account, never in
`config.json`. DPAPI ties it to this Windows account: other accounts cannot decrypt it, and
neither can a backup or a copy of the disk without your Windows credentials, but any program
running as you can. The install folder, `%USERPROFILE%\.nethersec-pc`, is also limited to your
Windows account. A key or URL that an older version left in `config.json` keeps working, and
the next scan that is not a dry run moves it into `secret.dpapi`. `install.ps1 -Uninstall`
removes the scheduled task.

## Files

| File | What it is |
|---|---|
| `pc-security-report.mjs` | The entry point the scheduled task runs |
| `pc-security-run.mjs` | Probes, glue and sending |
| `pc-security-lib.mjs` | Every decision, with no I/O |
| `install.ps1` | Installs, sets the key or webhook URL, uninstalls |
| `config.example.json`, `watch.example.json` | Starting points for `config.json` (no key or URL in it) and `watch.json` |
| `test/` | `node --test "pc/test/*.test.mjs"` from the repo root |
