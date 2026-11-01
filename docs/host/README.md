# Host scripts

Scripts for Linux servers, installed as systemd timers. They watch the box and report through
the [report protocol](../report-protocol.md) to a nethersec hub, or straight to a Discord
webhook, an ntfy topic or any JSON endpoint.

| Part | Script | Timer | What it does |
|---|---|---|---|
| Detector | `security-report.sh` | every 30 min | Read-only. The 13 checks below |
| Applier (optional) | `apply-aged-upgrades.sh` | hourly, and right before unattended-upgrades | Holds Ubuntu `-updates` and vendor apt upgrades until their version is a few days old, then installs them. **Ships in dry-run** (it holds, but installs nothing). See [applier.md](applier.md) |
| Flood detector (optional) | `flood-report.sh` | every minute | Connection, volume, HTTP and SMTP floods. **Its blocking ships off.** See [flood.md](flood.md) |
| Mitigations (by hand) | `docker-live-restore.sh`, `ipv4-options-drop.sh`, `kernel-modules-block.sh` | none | One-off hardening, each with `--check`. See [mitigations.md](mitigations.md) |
| Transport | `nethersec-report.sh` | none | Sends one report. Every script that posts goes through it |
| Status | `nethersec-status.sh` | none | Read-only summary of the detector, the applier and the flood detector, `--json` for agents |

## What is tested, and what is not

Every script has an offline harness in `host/test/` that mocks apt, journald, Docker, systemd,
nftables and the network, except `apt-introspect.py` (which needs a real apt cache through
`python3-apt`, so the harnesses feed its output in instead). `firewall-snapshot.sh`'s harness
checks the order of its sections, what it strips, and that its last line is the allowlist for
check 12. CI runs them all (`sh host/test/run-all.sh`) on
GitHub's `ubuntu-latest` runner, which is Ubuntu 24.04 as this is written, plus ShellCheck at
error level. The transport's harness also runs the real `curl` against a server on 127.0.0.1.

Run by hand, outside CI, before the first release: `install.sh` with the applier and the flood
detector on Ubuntu 24.04 booted with systemd in a throwaway container. That covered the real
installer, real systemd timers, real `apt` with security updates pending, the real Ubuntu CVE
lookup grading one of them High, the IP-options drop on real nftables, the status script, and
`--uninstall`, reporting to a local test listener. It found two bugs, both fixed and now covered
by the harnesses.

Not claimed: a container is not a server. Nothing here has run on a real server's kernel, with
Livepatch, needrestart, a Docker daemon, real SSH traffic, or a real flood, or reported to a real
hub, Discord webhook or ntfy server. The checks are written for Ubuntu. Nothing has run on Debian
or Raspberry Pi OS (see below); the harness only feeds in Raspberry Pi archive apt lines and
checks that checks 9 and 10 stay off away from Ubuntu.

## Safety rules

The design rules in [AGENTS.md](../../AGENTS.md) hold for every script here:

- **Cannot read is never all-clear.** A check that cannot read (apt locked, no journald, a
  lookup that timed out) sends nothing for its own signal: never a `0`, never a false
  `resolved`. All unreadable checks fold into one `monitor-unreadable` card (the flood
  detector's is `monitor-unreadable-flood`), which resolves when every check reads again.
- **Transition-only.** State lives in `/var/lib/nethersec`. A condition is reported once
  when it starts and once when it ends. One that stays raised is sent again at most every
  6 hours (`HOSTSEC_RESURFACE_SECS`; the flood detector's `HOSTSEC_FLOOD_RESURFACE_SECS` is
  1 hour), and the hub edits the open card.
- **Only a 2xx counts as sent.** A report that was not delivered (an error answer, a key the
  hub does not know yet, no network) changes no state, so the next run sends it again. That
  holds for a raise, a re-surface and a `resolved`, but not for the one-shot info notes. A
  raise that never got out and then cleared sends nothing, since the hub never heard of it.
  When a post of the detector or the flood detector gets no answer at all, the rest of that
  run's posts wait for the next run, so a hub that is down costs one timeout a run.
- **Quiet by default.** Routine patching makes no noise. Only a High or Critical fix stuck
  past its window, an applier that stopped, failed or left a package past its ceiling, or a
  check you set to `critical` pages.
- **A box cannot close its own security alert.** A `resolved` report tells the hub the box
  thinks it is fixed; a person presses Resolve.
- **Anything that acts ships dark.** The applier starts in dry-run (it still sets and
  releases its holds, but installs nothing) and the flood blocking starts off. You arm each
  per box after watching it.
- **Scripts never crash a timer.** The detectors always exit 0. A per-run cap limits posts
  (`HOSTSEC_MAX_POSTS`, default 8, for the detector; the flood detector and the applier have
  their own); what is over it is logged, never dropped silently, and goes on the next run
  (a one-shot info note does not).
- **No secret on a command line.** The key sits in `/etc/nethersec/report.env` (mode 600)
  and reaches `curl` on stdin (`-K -`).
- **Kill switches.** `sudo touch /etc/nethersec/disabled` pauses every script (the applier
  also releases its holds). `/etc/nethersec/apply-disabled` pauses the applier and releases
  its holds;
  `/etc/nethersec/flood-disabled` pauses the flood detector.

## Install

Requirements: Ubuntu with systemd, apt, `curl`, `python3` (standard library only) and
journald. Optional, each used when present: Docker, fail2ban, needrestart, `ss` (iproute2)
and `sshd`. On Ubuntu, checks 9 and 10 card a box without the `canonical-livepatch` snap or
nftables. Check 7 and the applier need `python3-apt` (without it check 7 cannot read); Ubuntu
has it, since unattended-upgrades depends on it. The detector reaches the network only to post
reports and, while an update or a reboot is pending, to grade CVEs at `ubuntu.com`.

From a clone of this repo, on the box, as root:

```sh
sudo bash host/install.sh --source web1 --report-url https://hub.example.com/v1/report --new-key --run-now
```

It copies the scripts into `/opt/nethersec` (root-owned, directories 755), writes
`/etc/nethersec/report.env` (mode 600), turns on the detector's timer, and prints one line
last:

```
web1 3f9a...c41e page
```

That is the line for the hub's keys file: the source, the SHA-256 of the key it made, and the
`page` flag. The key itself never leaves the box. For a device that should not page, or that
reports to one person, edit the flag on the hub's side (see the report protocol).

The order does not matter. Until the hub has the line, it refuses the box's reports (HTTP 401),
and each run sends them again, so a `--run-now` before the line is added loses nothing. Add the
line to the hub's `keys.txt` (or `key add` it with the hub's CLI), then send what is waiting with
`sudo systemctl start nethersec-security-report.service`, or wait for the next run.

Without a hub, post straight to a Discord webhook or an ntfy topic. A webhook URL is a
secret, so it goes on stdin, never on the command line:

```sh
read -rs URL && printf '%s\n' "$URL" | sudo bash host/install.sh --source web1 --url-stdin; unset URL
```

A Discord webhook URL picks the Discord format by itself. For ntfy, add `--format ntfy`; with
`--url-stdin --key-stdin` the first stdin line is the URL and the second an ntfy access token.
In these formats there are no cards, no Resolve button and no rate limit, and the two data
events (`reboot-pending`, `container-packages`) are skipped: they need the hub's store.

| Flag | What it does |
|---|---|
| `--source NAME` | This box's source name: a-z, 0-9 and `-`, 1 to 40 characters, starting with a letter or digit |
| `--report-url URL` / `--url-stdin` | Where reports go. A Discord webhook URL is refused on the command line |
| `--format FMT` | `hub` (default), `discord`, `ntfy` or `json` |
| `--new-key` | Make a key on the box (32 random bytes) and print the hub's keys-file line |
| `--key-stdin` | Read a key from stdin instead |
| `--replace-key` | Let `--new-key` or `--key-stdin` replace a key report.env already has |
| `--group LABEL` | A grouping label sent with every report |
| `--with-applier` | Also install the applier (dry-run). It also installs `python3-apt` if missing, turns on Docker live-restore where Docker is installed, and adds an unattended-upgrades drop-in. See [applier.md](applier.md) |
| `--with-flood` | Also install the flood detector (blocking off). See [flood.md](flood.md) |
| `--run-now` | Run each installed part once |
| `--check-path` | Only check the path to `/opt/nethersec` (no root needed, writes nothing) |
| `--uninstall` | Remove the units, the drop-in and `/opt/nethersec`. Keeps `/etc/nethersec`, `/var/lib/nethersec` and the mitigations |
| `--purge` | With `--uninstall`: also remove those two directories, and take off the IP-options drop and the module block |

An existing `report.env` is never replaced. A re-run changes only the values you pass and
says which (never echoing a URL or a key). A second `--new-key` refuses while a key is there,
because the hub may know it; add `--replace-key` and update the hub's keys file to rotate it.

**Updating.** `git pull` in the clone, then run `sudo bash host/install.sh` again. It swaps
the whole `/opt/nethersec` for the new copy and refreshes the units of every part already
installed. The commit it copied is in `/opt/nethersec/VERSION`.

**The path check.** The units run the scripts as root from `/opt/nethersec`. If any local
user could write a directory on that path (one without the sticky bit) or a script in it,
they could swap a script in before the next root run. `install.sh` refuses then and prints
the `chmod o-w` fix; check 6 of the detector cards it if the box drifts back later.

**Uninstalling.** `sudo bash host/install.sh --uninstall` first releases every package hold
the applier set, through its kill switch, and stops without removing anything if a hold stays
on: a hold with nothing left to release it would keep that package unpatched for good. Then
it clears the flood detector's drops, removes the units, the unattended-upgrades drop-in and
`/opt/nethersec`. Your settings and key stay in `/etc/nethersec` unless you add `--purge`.

## Operate

```sh
sudo sh /opt/nethersec/nethersec-status.sh                     # what ran, what is raised
sudo systemctl start nethersec-security-report.service         # run once now
journalctl -u nethersec-security-report.service -n 30          # its last log
systemctl list-timers 'nethersec-*'                            # next runs
sudo touch /etc/nethersec/disabled                             # pause every script
```

To send a test report with the box's own settings (systemd reads the env file, so the key
never touches a shell):

```sh
sudo systemd-run --pipe --wait -p EnvironmentFile=/etc/nethersec/report.env \
  sh /opt/nethersec/nethersec-report.sh --kind security --source web1 \
  --event selftest --severity warning --title "Selftest" --detail "sent by hand"
```

Never `source` the env file in a shell: a key with shell characters in it would be mangled.

### Status for agents

`nethersec-status.sh --json` prints one JSON object. Times are Unix seconds; `null` means
unknown or never. Without root it cannot read the mode-600 files and says `unknown` or `null`
for what is in them. It never prints the key or the URL.

```json
{
  "v": 1, "installed": true, "version": "1a2b3c4d5e6f", "source": "web1",
  "transport": {"format": "hub", "url": "set", "key": "set"},
  "paused": {"all": false, "applier": false, "flood": false},
  "timers": [{"part": "security-report", "timer_enabled": "enabled", "timer_active": "active",
              "last_start": 1790000000, "last_result": "success", "last_done": 1790000005}],
  "checks": [{"part": "security-report", "event": "security-updates", "state": "raised",
              "severity": "critical", "asserted_at": 1790000000}],
  "unreadable": ["ssh-auth"],
  "detector": {"pending_security_updates": 3, "oldest_pending_since": 1789900000,
               "reboot_pending_since": null, "container_lists": 2},
  "applier": {"installed": true, "enabled": true, "dry_run": true, "heartbeat": 1790000000,
              "holds": 1, "signals": [{"event": "apply-stale-cache", "severity": "warning",
              "posted_at": 1790000000}]},
  "flood": {"installed": false, "mitigate": false}
}
```

`checks` lists every check of the detector and the flood detector as `raised` or `ok`.
`raised` means a raise was posted and no `resolved` since; `ok` only means none is open. A
check that could not read on the last run keeps its last state here and is also named under
`unreadable`. `last_done` is the script's own end-of-run stamp, `asserted_at` when a raised check was last
posted. The applier's `signals` are the last time each of its cards was posted; they do not
clear by themselves.

## The checks

| # | Check | Event | Default |
|---|---|---|---|
| 1 | Pending security updates (`apt-get -s dist-upgrade`, the `-security` pocket) | `security-updates` (+ `security-updates-applied`) | **Silent** while within its window (26h, per package). **Page** only when one stuck past its window fixes a High or Critical Ubuntu CVE. A stuck batch with no High/Critical is one quiet card (unattended-upgrades looks stopped). A quiet info note when a batch with a High/Critical fix clears |
| 2 | Reboot pending (`/var/run/reboot-required`, or a kernel newer than the running one) | `reboot-security` (+ `reboot-pending`, data) | Quiet card only when a staged fix for a High/Critical CVE is not live yet. Everything else goes into the hub's weekly summary |
| 3 | SSH login burst (journald) | `ssh-auth-burst` | Quiet card at 2000 or more failures a run |
| 4 | Log error rate (journald `-p err` + container logs) | `log-error-rate` | Quiet card at 600 or more errors an hour |
| 5 | Applier backstop | `apply-backstop` | **Page** when the applier has not finished a run for 3h, or a hold it set is older than its ceiling (10 days). Inert without the applier |
| 6 | Writable script path | `script-path-writable` | Quiet card |
| 7 | Vendor package updates not installed (non-distro apt repos) | `thirdparty-updates` | Quiet card once one has waited 7 days |
| 8 | Docker live-restore off | `docker-live-restore` | Quiet card. Inert without Docker |
| 9 | Livepatch not running | `livepatch-off` | Quiet card. On by default on Ubuntu |
| 10 | IP-options drop off | `ipv4-options-drop-off` | Quiet card. On by default on Ubuntu |
| 11 | SSH accepts passwords (`sshd -T`, or `sshd -G` when sshd has not started yet) | `ssh-password-auth` | Quiet card. Inert without sshd |
| 12 | Unexpected listener (`ss`, non-loopback sockets) | `unexpected-listener` | Quiet card. **Off until you set the allowlist** |
| 13 | Container OS packages | `container-packages` (data) | No card from the box: the hub matches the lists against OSV |

### 1. Pending security updates

The check keys off the CVE, not the package name. For each pending `-security` package,
[`cve-severity.py`](../../host/cve-severity.py) finds the Ubuntu security notice that ships
its exact candidate version, then that notice's CVEs and their Ubuntu priority. Only a High
or Critical fix can page or get a done note; low and medium updates that apply on time stay
silent.

- **Within its window: silent.** unattended-upgrades applies the `-security` pocket once a
  day, so a fix that lands in the evening is normally gone by morning. A pending update stays
  quiet for 26 hours (`HOSTSEC_SECUPDATE_GRACE_SECS`; `0` judges at once).
- **The window is per package**, from when that package was first seen pending. A fix that
  joins while an older batch is still pending gets its own full window instead of the batch's
  age. A package that stays pending keeps its clock, even when a newer version arrives. One
  that drops out for a run or two (up to 6 hours) and comes back at the same version keeps it
  too; one that comes back at a new version starts fresh. The clocks live in
  `/var/lib/nethersec/first-seen.security-updates.tsv`.
- **Stuck past its window: a page** only if it fixes a High or Critical CVE. A stuck batch that
  is only low or medium gets one quiet card. A grade the lookup could not finish folds into
  `monitor-unreadable`: a stuck update is never dropped, and a lookup outage never makes a page.
- **Cleared:** a quiet info note, only when the batch held a High or Critical fix.

The lookup runs only while something is pending, caches its answers in
`/var/lib/nethersec/cve-cache`, has a hard timeout and a budget per run, and turns every
failure into `unknown` or `error`, never a made-up High. On a box with no way out to
`ubuntu.com`, set `HOSTSEC_CVE_LOOKUP=0`: a stuck update then gets a quiet card instead of a
graded page, and check 2 grades nothing, so the box reads "not checked".

### 2. Pending reboots

A box that cannot be rebooted often would carry a card for every staged update. So each run
reads the staged packages (`/var/run/reboot-required.pkgs`, plus any installed kernel image
of the running kernel's base version and flavor, such as `linux-image-6.8.0-*-generic`, that
is newer than the running one, since with Livepatch on Ubuntu never sets the flag for a kernel)
and grades every High and Critical CVE those versions fix. A CVE is **live**, already
protecting the box, when:

- for a kernel package: Livepatch is applied to the running kernel and lists that CVE. The
  Livepatch client is a snap, which cannot start under the unit's `NoNewPrivileges`, so when
  the direct call returns no JSON the same read-only command runs once in a short transient
  unit (`systemd-run`, 20 s);
- for any other package: `needrestart -b` (list mode, restarts nothing) names no service
  still on the old code.

Some High or Critical CVE not live: a quiet `reboot-security` card naming them. All live, or
none: no card. A lookup that could not finish: no card and no resolve, and the box reads "not
checked". A newer kernel that still cannot be graded 3 days after its install
(`HOSTSEC_REBOOT_UNGRADED_SECS`) gets the card anyway.

Whatever the result, the box sends a `reboot-pending` data report (the format is in the
[report protocol](../report-protocol.md)) when it changes and about every 20 hours otherwise,
and a `resolved` one after the reboot. The hub posts one weekly summary of every box with a
reboot pending. Known gap: for a package other than a kernel image, only the CVEs of the
installed version's own notice count, so a fix that came with an in-between version is missed.

### 3 and 4. SSH bursts and log errors

A server on the internet sees hundreds to thousands of failed SSH logins every half hour from
scanners. On a box that takes keys only, none can land, so the burst check is a quiet card
over a high threshold (`HOSTSEC_SSH_BURST`, 2000). Set `HOSTSEC_SSH_SEVERITY=critical` and a
lower threshold only where password logins are on. The fail2ban ban count is added when
fail2ban is there.

The log check counts error lines since the last run in journald (`-p err`, minus every sshd
line, which check 3 owns) and in each running container's logs, and works out errors an hour.
Container lines match whole error words, so `errors=0` or `[api.ErrorHandler]` do not count.
One crash-looping container can write thousands of lines, so the default is a quiet card at
600 or more an hour. Watch a box's normal floor, then lower `HOSTSEC_LOGERR_BURST`; add the
box's own noise to `HOSTSEC_LOGERR_EXCLUDE_RE`.

### 7. Vendor packages

unattended-upgrades installs only distro packages, so an update from a vendor's own apt repo
(a vendor's own apt repository, such as Docker's) can wait forever unless the applier is live. The
check reads every installed package whose candidate comes from a non-distro origin
(`apt-introspect.py`, held packages included) and raises one quiet card per box once any has
had a newer version for 7 days (`HOSTSEC_THIRDPARTY_GRACE_SECS`). A newer vendor release does
not restart the clock. `HOSTSEC_THIRDPARTY_IGNORE` skips named packages.

### 12. The listener allowlist

Tokens are `<proto>/<address>:<port>` exactly as `ss` prints the local address
(`tcp/0.0.0.0:22`, `tcp/[::]:22`), with `*` for any address or any port (`tcp/*:443`), separated
by spaces. Loopback sockets are never checked. Run `sudo bash /opt/nethersec/firewall-snapshot.sh`,
copy its `HOSTSEC_LISTEN_ALLOW="..."` line into `/etc/nethersec/report.env`, and swap any
port that changes on every restart for `*`. A different set of listeners re-posts at once. A
Docker port published without `docker-proxy` has no socket, so a firewall in front of the box
is worth checking on its own.

### 13. Container OS packages

Nothing else reads the OS packages inside a container image, and an image whose maintainer
stopped releasing keeps its old base. For each running container that publishes a port (a
host binding, loopback included, since a proxy in front still serves it) or uses the host
network, the detector streams `/etc/os-release` and the dpkg or apk database out with
`docker cp ... -` into `tar -xO`. Nothing runs inside the container and nothing lands on disk.
It lists source packages (the dpkg `Source:` field, the apk origin), because OSV keys Debian,
Ubuntu and Alpine advisories on those.

Each container is one `container-packages` data report, sent when its list changes and about
every 20 hours otherwise, and `resolved` once the container stops publishing. At most 12 lists
go out a run (`HOSTSEC_CTRPKG_MAX_POSTS`), outside the alert cap. The hub opens one card per
image with a fixable critical or high CVE.

## Tuning

The detector's settings go in `/etc/nethersec/report.env`;
[report.env.example](../../host/report.env.example) explains the common ones. The full list,
with defaults, is in the header of [security-report.sh](../../host/security-report.sh). Check 5
also reads the applier's `HOSTSEC_APPLY_CEILING_DAYS` from `/etc/nethersec/apply.env`. The
main ones:

| Variable | Default | What it does |
|---|---|---|
| `HOSTSEC_SECUPDATE_GRACE_SECS` | 93600 (26h) | How long a pending security update stays silent |
| `HOSTSEC_CVE_LOOKUP` | 1 | 0 turns off CVE grading: a stuck update is a quiet card |
| `HOSTSEC_SSH_BURST` / `HOSTSEC_SSH_SEVERITY` | 2000 / warning | Check 3 |
| `HOSTSEC_LOGERR_BURST` / `HOSTSEC_LOGERR_SEVERITY` / `HOSTSEC_LOGERR_ENABLE` | 600 / warning / 1 | Check 4 |
| `HOSTSEC_LOGERR_EXCLUDE_RE` | none | Extra noise to leave out of check 4 |
| `HOSTSEC_THIRDPARTY_GRACE_SECS` / `HOSTSEC_THIRDPARTY_IGNORE` | 7 days / none | Check 7 |
| `HOSTSEC_LIVEPATCH_CHECK` / `HOSTSEC_IPOPT_CHECK` | auto (on on Ubuntu) | Checks 9 and 10: `1`, `0` or `auto` |
| `HOSTSEC_SSHD_CHECK` | 1 | Check 11 |
| `HOSTSEC_LISTEN_ALLOW` | unset (check off) | Check 12 |
| `HOSTSEC_CTRPKG_ENABLE` | 1 | Check 13 |
| `HOSTSEC_SECURITY_ORIGIN_RE` | none | Extra apt origins that count as security updates |
| `HOSTSEC_RESURFACE_SECS` | 21600 (6h) | How often a raised check is sent again |
| `HOSTSEC_MAX_POSTS` | 8 | Alert posts per run |

## Raspberry Pi OS

The detector can run on Raspberry Pi OS, though nothing in this repo tests it there. Three
settings make sense in its `report.env`:

- `HOSTSEC_SECURITY_ORIGIN_RE=Raspberry.Pi.Foundation:`. The Raspberry Pi archive ships
  Chromium, the kernel, the firmware and libc6 from suite `stable`, not `-security`, so
  without this a stuck one is never seen.
- `HOSTSEC_CVE_LOOKUP=0`. The grading reads Ubuntu's notices and the Pi runs Debian, so a
  stuck update is a quiet card instead.
- No applier and no flood detector, unless the Pi serves the internet.

Livepatch and the IP-options drop checks stay off, since os-release does not say Ubuntu. A Pi
can be carried off, so give its key no `page` flag on the hub, or a `dm=` flag to send its
reports to one person (see the [report protocol](../report-protocol.md)). A `dm=` key cannot
send the two data events (`reboot-pending`, `container-packages`): the hub refuses them (HTTP
403). The box logs that once and sends the same data again only after its usual resend interval
(about 20 hours), or at once when the data changes.
