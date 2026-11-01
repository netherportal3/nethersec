# PC scanner (Windows)

The nethersec PC scanner checks one Windows PC for missing security fixes and protection
that was turned off. A scheduled task runs it every 6 hours and 5 minutes after you log on.
When something changes, it sends one short report, either to your nethersec hub, which passes
it to you as a Discord direct message, or straight to a Discord webhook in a private channel.

It only reads. It never installs, upgrades or removes anything, and never changes a Windows
setting. Besides its own folder and the caches of the programs it runs (winget refreshes its
source lists), the one thing it changes: the WSL check runs `apt-get update` inside a WSL distro
that is already running, which refreshes that distro's package lists.

The code is in [`pc/`](../../pc). It is plain Node.js with no dependencies.

## What it checks

| Event | Bad when | Grace |
|---|---|---|
| `exploited` | An entry in CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list matches something installed (watch entries carry the matchers; Windows entries map to the Windows Update check). The only check that sends `critical`: when an update is waiting, or the scanner cannot tell whether one is. If you already have the newest version it sends one `warning` notice, which later clears without a message. It clears only on proof: the app's version went up and a good `winget upgrade` read shows no update waiting, the app was gone on 2 reads in a row, or a complete Windows Update read shows nothing waiting. A cleared flaw comes back if the next read that can see the app finds an older version, or, for an app that was removed, finds it back with an update waiting. Until such a read (while the app stays gone or the winget lists cannot be read), it waits for up to a year. | none. The first run records the whole list and only reports entries added in the last 30 days. |
| `windows-updates` | A security update (it has an MSRC severity or is in the Security Updates category) is not installed. The report also says when a restart is pending or updates are paused. | 7 days from release |
| `defender` | The Defender service or antivirus is off, real-time protection is off, or the definitions are older than 3 days. Passive mode (another antivirus is in charge) is fine. | none |
| `firewall` | Any firewall profile is off. | none |
| `apps-behind` | A watched app has a newer version in `winget upgrade`. One report lists them all. A newer **major** version is not "behind" unless the entry has `followsMajor`. | 7 days per app, from the first run that saw it behind. A newer release does not restart the clock. |
| `apps-eol` | A package listed under `eol` in `watch.json` is installed. | none |
| `runtimes` | Node: a newer release in the same major is a security release, or the major is past end of life. Go: a newer patch of the same minor, or the minor is not one of the two supported lines. Java (Azul Zulu under `Program Files\Zulu`): Azul has a newer build of the same major. | 7 days (Node counts from the security release date). A Node major past end of life alerts at once. |
| `wsl-updates` | A WSL distro with apt has upgrades from a `-security` pocket. Checked about once a day (at most once every 20 hours), and only while the distro is already running; `docker-desktop` is skipped. A stopped distro keeps its last result. The scanner looks again right before each distro and leaves one that stopped since the list. A small race remains: a distro that stops in the moment between that look and the check is started by it. Set `wsl.startStopped` to check stopped ones too (see [Tuning](#tuning)). The scanner never stops a distro. | alerts on the second daily check in a row |
| `monitor-unreadable` | A check could not read for over 2 days. | 2 days |

## How it decides when to report

- **Transition-only.** A report goes out when a check turns bad or good, when an active report
  gains an item (a new app falls behind) or gets more severe, and as a reminder once a week
  while it stays bad.
  Never on every run. At most 5 reports per run; the rest wait for the next run.
- **Cannot read means no change.** A check that fails to read changes nothing, so it never
  sends a false "fixed". That covers winget timing out, exiting with an error without a
  complete answer, printing a table row the scanner cannot read (it could be any app), or
  printing an "N upgrades available" line that does not match the rows;
  a Windows Update search that finishes with errors (it can still prove an update is
  waiting, never that none is); no network; and a `watch.json` that is not valid JSON
  (apps-behind, apps-eol and exploited then stay as they were). A check unreadable for over
  2 days sends one `monitor-unreadable` report. Turning a check off ends its cannot-read alert.
- **One flaky read never clears.** An app that drops out of the behind list stays in it
  until it is missing on 2 good reads in a row, or `winget list` shows its version changed.
- **Grace windows** keep routine patching quiet: most things are fixed by normal updates
  within a week.
- **Time budget.** Checks get 14 minutes and reports 18, under the task's 20-minute limit.
  A check with no time left counts as unreadable; a program that runs too long is killed
  with everything it started. State is saved before sending and after each delivered
  report, so a run cut short sends again at most the one report it was sending.

## What it reads

| What | Used by |
|---|---|
| Windows PowerShell 5.1: Defender status (`Get-MpComputerStatus`), firewall profiles (`Get-NetFirewallProfile`), and the registry values for the Windows version, a pending restart and paused updates | `defender`, `firewall`, `windows-updates` |
| The Windows Update Agent: a search for updates that are not installed, like the one Settings runs. It only searches. | `windows-updates`, `exploited` |
| `winget upgrade --include-unknown --include-pinned` and `winget list` | `apps-behind`, `apps-eol`, `exploited` |
| `where node` and `node --version`, `go version`, and the `release` file of each JDK under `Program Files\Zulu` | `runtimes` |
| `wsl.exe -l -v` (again right before each distro), then in each running distro, as root: `apt-get update` and `apt-get -s dist-upgrade` (a simulation that installs nothing) | `wsl-updates` |
| Public feeds, cached in `cache/`: the nodejs.org release index, endoflife.date's Node.js dates, the go.dev release list, Azul's package API (one query per installed Java major), and CISA's KEV catalog (about once a day) | `runtimes`, `exploited` |

The feeds see an ordinary download: your IP address, a nethersec user agent, and no version
number, except that the Azul query names the Java major version (and asks for Windows x64
builds). A runtime's feeds are asked only when that runtime is found, so nodejs.org and
endoflife.date can tell you have Node, go.dev that you have Go, and Azul that you have a Zulu
JDK. winget contacts its own sources when it searches, and Windows Update its update service.

It writes only to its own folder: `state.json`, `last-run.json`, `cache/`, and `secret.dpapi`
and `config.json` when the installer saves a key or a webhook URL (or a run moves one out of an
older `config.json`). The exceptions are the WSL package lists above and the caches the
programs it runs keep for themselves: winget refreshes its source lists, and the scanner runs it
with `--accept-source-agreements`, which accepts winget's source agreements for you. It never
installs, upgrades or uninstalls anything, never changes a Windows setting,
never starts a stopped WSL distro unless you set `wsl.startStopped` (except in the small race
noted under `wsl-updates`), and never stops one.

## Requirements

- Windows 10 or 11. The task runs as you, without elevation.
- [Node.js](https://nodejs.org) 22 or newer on `PATH`. The scanner needs no npm packages.
  The tests run on Node 22 and 24.
- winget (App Installer, part of current Windows) for the app checks. Without it they report
  that they cannot read.
- Windows PowerShell 5.1, which is part of Windows. Several checks and the DPAPI calls use it.

## Install

From the `pc` folder of a nethersec checkout, in a normal (not elevated) PowerShell window:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -WhatIf   # shows what it would do
powershell -ExecutionPolicy Bypass -File .\install.ps1           # installs; sends nothing yet
```

Then pick a delivery mode below and run the installer once more with `-NewKey` or `-Webhook`.

The installer:

- copies the scanner to `%USERPROFILE%\.nethersec-pc`. Not AppData: a packaged (MSIX) app can
  have its AppData writes redirected to a private copy, and the scheduled task would not see
  files written that way.
- limits that folder to your Windows account. It turns off the permissions inherited from your
  profile and leaves one entry, your account with full control, which every file made in the
  folder inherits. `config.json` gets the same single entry of its own, and so does
  `secret.dpapi` when `-NewKey` or `-Webhook` writes it; the installer warns if any other entry
  is left on either. This keeps other accounts on the PC out of your files. On its own it is not
  encryption (an administrator of the PC can take ownership of a file), so the key or webhook URL
  is also encrypted: see [How the key and the URL are kept](#how-the-key-and-the-url-are-kept).
- creates `config.json` and `watch.json` from the examples when they are missing.
- registers the task `nethersec-pc-security-report`: every 6 hours from a start time picked at
  random on each install, with up to 30 minutes of random delay, and 5 minutes after logon; runs late if the PC was asleep, as you without elevation, only while you are
  logged on, stopped after 20 minutes. It launches node through `conhost.exe --headless`, so no
  console window flashes. (Task Scheduler's result code does not tell you how a scan went:
  the scanner exits 0 even when it finds problems. Read `last-run.json` instead.)

Running the installer again updates the scripts and the task and keeps your files, key and URL.
When `config.json` still holds a key or webhook URL from an older version, it says so (see
[Moving a key out of an older config.json](#moving-a-key-out-of-an-older-configjson)).

## Delivery

`delivery` in `config.json` picks one of two modes. Until the chosen mode has everything it
needs, runs still check and save state, but send nothing, and a dry run says what is missing.
Either way, only a 2xx answer counts as sent; anything else leaves the report pending for the
next run, and redirects are never followed.

### Through the hub, by direct message

The hub checks the key and, because the key has the `dm=` flag, sends this PC's reports to you
as Discord direct messages and nowhere else: no channel, no card, no ping. Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -NewKey -HubUrl https://hub.example.com -DiscordUserId 123456789012345678
```

It makes a key (32 random bytes as 64 hex characters), saves it encrypted in `secret.dpapi`,
sets `"delivery": "hub"` and your `hubUrl` in `config.json`, and prints the line for the hub:

```
pc <SHA-256 of the key> dm=<your Discord user ID>
```

That is the source, the SHA-256 of the key text, and the `dm=` flag. The key itself is never
printed. Add the line to the hub's `keys.txt` (or use the hub's `key add` command). Running
`-NewKey` again replaces the key; replace the hub's line too. `secret.dpapi` holds one secret,
so `-NewKey` also replaces a webhook URL saved earlier, and `-Webhook` a key.

- Your Discord user ID: turn on Developer Mode (User Settings > Advanced), then right-click your
  name and pick Copy User ID. Without `-DiscordUserId` the line ends in a placeholder to fill in.
- `hubUrl` is the hub's address. The scanner posts to `<hubUrl>/v1/report` (see the
  [report protocol](../report-protocol.md)). It must be `https://`, except to a loopback or
  private IP address (`localhost`, `::1`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, the `100.64.0.0/10` range a VPN or tailnet often uses, or an IPv6 unique
  local address), where plain `http://` is allowed. For a private host name over plain http, set `"allowHttp": true`;
  the key then crosses that network unencrypted.
- Several PCs: give each its own `source` in `config.json` (lowercase letters, digits and
  dashes, such as `laptop`) before running `-NewKey`. A key belongs to one source.
- When the hub answers 401, 403, 404, 429 or 5xx, the rest of that run's reports wait for the
  next run, since they would fail the same way. A 400 or 413 skips only that report.

### Straight to a Discord webhook

For a private channel, without a hub. There is no card state and no Resolve button: each report
is a new message, an embed colored by severity, and green when a problem is fixed. Mentions
are turned off, and names from the PC are escaped so they cannot format the message.

1. In Discord: the channel's settings > Integrations > Webhooks > New Webhook > Copy Webhook URL.
   Keep the channel private: everyone who can read it sees which programs on your PC are out
   of date.
2. Run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1 -Webhook
   ```

   It asks for the URL (it does not show while you paste it), passes it to the scanner on
   stdin, saves it encrypted in `secret.dpapi`, and sets `"delivery": "webhook"` in
   `config.json`. Only `https://` URLs on `discord.com` (or its `ptb` and `canary` hosts, or
   `discordapp.com`) under `/api/webhooks/` are accepted.

Anyone with the URL can post in that channel: treat it like a password. To revoke it, delete
the webhook in Discord.

### How the key and the URL are kept

The key or the webhook URL is in `secret.dpapi` in the install folder, encrypted with Windows
DPAPI for your account (current-user scope), never in `config.json`. `-NewKey` and `-Webhook`
encrypt it, check that it decrypts, write `secret.dpapi`, and only then update `config.json`.
Each run decrypts it again: the scanner starts Windows PowerShell, gives it the encrypted text
on stdin, and reads the plain text back from its stdout, a pipe to the scanner. A dry run
decrypts it too, so its `delivery:` line shows whether reports can go out.

- **What it protects against:** other Windows accounts on the PC cannot decrypt it, and neither
  can a backup or a copy of the disk without your Windows credentials. The folder permissions
  also keep other accounts from reading the file at all.
- **What it does not:** DPAPI ties the secret to your Windows account, not to the scanner. Any
  program running as you can decrypt it, the same way the scanner does, and so can an
  administrator who runs code on the PC while you are logged on.
- **When it stops decrypting:** a `secret.dpapi` copied from another account or PC, a damaged
  file, or a password reset by an administrator (rather than you changing your password) can
  leave it unreadable. The run then sends nothing and the reports wait for the next run. The
  `delivery:` line and a `config problem:` line (in a dry run and in `last-run.json`) say so
  and name the fix: run `install.ps1 -NewKey` again and replace the hub's line, or run
  `install.ps1 -Webhook` again. When PowerShell does not answer at all (it timed out, say), the
  reports also wait, and the `delivery:` line says why.

The key and the URL are never put on a command line or in an environment variable, printed, or
written to `last-run.json`. The installer lets node make the key itself and pipes the webhook
URL in on stdin; node hands either one to PowerShell on stdin. Inside that PowerShell the plain
text passes only through .NET calls and the pipe, never a PowerShell command's parameters or
output. PowerShell's module logging records command parameters and a transcript records command
output, so neither has it to record if your PC turns them on. Result lines carry only a status
code or a fixed reason, and an error about a broken `config.json` names at most the line and
column, never the text.

### Moving a key out of an older config.json

Older versions kept the key or webhook URL in `config.json` in plain text. One that is still
there keeps working. The next run that is not a dry run moves it: it encrypts it into
`secret.dpapi`, checks that it decrypts, and then takes `key` and `webhookUrl` out of
`config.json`, keeping your other settings. A `delivery note:` line in that run's output and
`deliveryNotes` in `last-run.json` say it happened. A dry run moves nothing and says the next run
will. If the move fails, `config.json` is left as it was, reports still go out with the old
value, a `config problem:` line says why, and the next run tries again.

Running the installer again does not move it, but says when `config.json` still holds one and
how to run the scanner once now. A `key` or `webhookUrl` in `config.json` that the delivery mode
does not use (a `webhookUrl` with `"delivery": "hub"`) is not moved. Unless a run takes it out
along with a moved one, a `config problem:` line asks you to delete it.

## Config

`config.json` (from [`config.example.json`](../../pc/config.example.json)):

| Key | Default | What it is |
|---|---|---|
| `delivery` | `"hub"` | `"hub"` or `"webhook"` |
| `hubUrl` | `""` | The hub's address, for `"hub"` |
| `allowHttp` | `false` | Allow `http://` to a host name (an IP address in a private range is always allowed) |
| `source` | `"pc"` | The report protocol's source name; must match the hub's line for this key |
| `disabled` | `false` | `true` turns the scanner off. An empty file named `disabled` in the folder does the same. |
| `appGraceDays`, `runtimeGraceDays`, `windowsGraceDays` | `7` | Grace windows |
| `defenderSignatureMaxDays` | `3` | How old the virus definitions may get |
| `reminderDays` | `7` | How often a standing problem is sent again |
| `unreadableAlertDays` | `2` | How long a check may fail to read before `monitor-unreadable` |
| `maxPostsPerRun` | `5` | Reports per run (the hub also limits a `dm=` source to 15 an hour) |
| `checkBudgetMinutes`, `reportBudgetMinutes` | `14`, `18` | Time budgets; keep both under the task's 20 minutes |
| `wsl.enabled`, `wsl.startStopped`, `wsl.skip` | `true`, `false`, `["^docker-desktop"]` | The WSL check, see [Tuning](#tuning) |
| `runtimes.node`, `runtimes.go`, `runtimes.java` | `true` | Each runtime check |
| `kev.enabled` | `true` | The exploited-flaws check |

There is no key or webhook URL in `config.json`: they are in `secret.dpapi` (see
[How the key and the URL are kept](#how-the-key-and-the-url-are-kept)).

Problems in the file show as `config problem:` lines in a dry run and in `last-run.json`.

## Watch list

`watch.json` is your own list of apps; it is never committed (the `pc/.gitignore` keeps it,
`config.json` and the state files out of git). [`watch.example.json`](../../pc/watch.example.json)
is a generic start: common browsers, a PDF reader, a few developer tools and runtimes. Add the
apps you care about. Entry fields:

```json
{ "id": "Vendor.App", "name": "Some App", "followsMajor": true, "kev": [{ "vendorProject": "^Vendor$", "product": "^Some App" }] }
```

- `id` (the exact winget id), or `idPattern` / `namePattern` (a case-insensitive regex) for
  packages with several ids or no winget id. `winget list` shows the ids.
- `followsMajor`: count a newer major as behind. Use it for apps whose major number moves with
  every release, such as browsers or year-based versions. `lineParts: 2` makes the minor the
  release line (Go 1.26 -> 1.27).
- `check: "runtimes"`: leave updates to the runtimes check (Node, Go, Java); the entry is still
  used for exploited flaws.
- `kev`: matchers for the `vendorProject` and `product` fields of CISA's catalog (regex; every
  field given must match).
- `update`: the fix command to show, if not `winget upgrade --id <id>`.

`eol` entries use the same `id` / `idPattern` / `namePattern`, plus an optional `note` that
replaces the default advice in the report.

An entry with a pattern that does not compile is skipped and named in a `config problem:`
line; whatever it reported before is kept as it was until you fix it.

## Tuning

- **Quieter or faster:** raise or lower the grace days and `reminderDays`.
- **Turn a check off:** `runtimes.node`, `runtimes.go` or `runtimes.java` set to `false`,
  `"wsl": { "enabled": false }`, or `"kev": { "enabled": false }`. Turning a check off also
  ends its cannot-read alert.
- **`wsl.startStopped`** (default `false`): also check distros that are not running. Starting
  a distro boots it like opening a terminal does: its systemd units and `[boot]` command run,
  and on Ubuntu `apt-daily-upgrade` may start installing packages and keep it up for a while.
  Turn it on only if that is fine. `wsl.skip` lists name patterns to leave alone; a pattern
  that does not compile stops the WSL check (it shows as cannot read) until it is fixed.

## Reading a dry run

```powershell
node $env:USERPROFILE\.nethersec-pc\pc-security-report.mjs --dry-run
node $env:USERPROFILE\.nethersec-pc\pc-security-report.mjs --ignore-grace   # everything behind now
```

`--dry-run` runs every check, prints one line per event and the JSON it would send, and saves
and sends nothing. The WSL check still runs `apt-get update` in a running distro (and in
stopped ones with `wsl.startStopped`), which refreshes its package lists. `--ignore-grace`
reports everything behind regardless of grace windows (it implies `--dry-run`). `--json`
prints the findings as JSON. The `delivery:` line says whether reports can go out, and a
`delivery note:` line says when a key or URL is still waiting in `config.json` to be moved.
Statuses:

- `ALERT`: bad now and past grace; its report text follows.
- `waiting`: bad, still inside the grace window (`within grace:` lines say what).
- `ok`, or `CANNOT READ` with the reason (nothing changes for that check this run).
- `off`: the WSL or exploited-flaws check is turned off in `config.json`.

`note:` lines carry context: packages skipped as a newer major, Windows exploited-flaw entries
treated as fixed because no security update is waiting, and which WSL distros were checked.

The exit code is 0 even when checks find problems; it is non-zero only for a crash, an unknown
option or one missing its value, or a setup command that could not finish.

## Files

All in `%USERPROFILE%\.nethersec-pc`:

| File | What it is |
|---|---|
| `config.json` | Your settings. No key, no URL. |
| `secret.dpapi` | The key (hub) or the webhook URL (webhook), encrypted with DPAPI for your Windows account. Written by `install.ps1 -NewKey` or `-Webhook`; each replaces it. |
| `watch.json` | Your watch list |
| `state.json` | Clocks and what was last sent. If it gets corrupted, it is moved aside as `state.json.bad-<time>` and the scanner starts fresh (clocks restart, the exploited list is recorded again). |
| `last-run.json` | A summary of the last run that was not a dry run: statuses, what could not read, and each report's result. No key, no URL. |
| `cache/` | The public feeds, so the CISA list is fetched about once a day and the release lists every few hours |

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
```

It removes the scheduled task and keeps the folder. Delete `%USERPROFILE%\.nethersec-pc` to
remove `secret.dpapi` (the key or webhook URL) and the state. Then remove this PC's line from the hub's keys
file, or delete the webhook in Discord.

## Limits

- **Not covered:** local Docker images (Docker Desktop itself can be in the watch list), apps
  winget does not track (no Source in `winget list`), apps that update themselves outside winget
  (Microsoft Office, for one), Java other than Azul Zulu under `Program Files\Zulu`, browser
  extensions, and antivirus products other than Defender (Defender in passive mode is accepted;
  the other product is not checked).
- **Exploited-flaw matching is by name.** A CISA entry matches by vendor and product, not by
  version range. A match says you have that product; the scanner then looks at whether an update
  is waiting. One CVE is reported against the first watched app it matches. Windows entries count
  as fixed when no Windows security update is waiting.
- **Timing.** It runs only while you are logged on, every 6 hours, so a problem can take up to
  6 hours plus its grace window to show. WSL updates and exploited flaws can take longer: the
  WSL check and the CISA list download each happen about once a day.
- **winget output can change** between winget versions. Output the parser does not recognize
  counts as cannot-read, never as all clear. So does a whole winget read with one table row it
  cannot read. On a Windows that is not in English, the table columns are read by position.
- **The key is tied to your Windows account, not to the scanner.** Any program running as you
  can decrypt `secret.dpapi`, as the scanner does. See
  [How the key and the URL are kept](#how-the-key-and-the-url-are-kept).
- **What the tests cover.** CI runs `node --test "pc/test/*.test.mjs"` on Linux, with stand-ins
  for the probes (the code that runs Windows commands and downloads the feeds): winget and WSL
  parsing on sample output, version math, every check's rules, report transitions, the message
  text, the config checks, the winget probe and the WSL probe's distro loop (with stand-ins for
  `winget.exe` and `wsl.exe`), a whole scan sent to a hub (including real HTTP requests to a test
  server on loopback, one of them a redirect that is not followed) and to a webhook, and the
  `--new-key` and `--set-webhook` commands. With a stand-in for PowerShell's DPAPI, it also
  covers reading the key or URL from `secret.dpapi`, a file this account cannot decrypt, moving
  one out of an older `config.json`, and that neither ever reaches a program's arguments or environment, the
  console, `last-run.json` or `state.json`. `install.ps1` and the scanner's embedded PowerShell
  (the DPAPI calls included) are only parse-checked in CI, never run there; a test checks the
  DPAPI scripts keep the shape described above. Not covered by CI: a real install and Task
  Scheduler run, the folder permissions, real DPAPI, real Windows Update, Defender, firewall,
  winget and WSL output, the other probe code (what it runs, the feed downloads and their
  cache), and real delivery to a hub or Discord.
