# Release-age applier (`apply-aged-upgrades.sh`)

The write-side twin of the detector. Where `security-report.sh` only watches, this one installs
apt upgrades, but only once an exact version has been visible to the box for a few days
(default 4). It is the apt version of npm's `minimumReleaseAge`: a compromised or broken
version has time to be caught and pulled before it lands on your box.

**It ships in dry-run.** With `HOSTSEC_APPLY_DRYRUN=1` (the default in `apply.env`) it sorts
and holds packages as usual but only logs the set it would install. Watch a clean cycle in the
journal, then set `HOSTSEC_APPLY_DRYRUN=0` in `/etc/nethersec/apply.env` on that box. Only the
exact value `0` installs: any other value (empty, `false`, a typo) stays in dry-run and says so
in the journal.

Like the rest of `host/`, it is tested by an offline harness with a mock apt
(`host/test/apply-aged-upgrades.test.sh`), not yet on a live server.

## Policy

| Class | Example origin | What happens |
|---|---|---|
| Ubuntu `-security` and ESM security | `security.ubuntu.com` | **Left alone.** unattended-upgrades installs it within a day; delaying a signed fix for a known CVE only lengthens the exposure |
| A crown-jewel package from Ubuntu | `openssl` from `-updates` | **Installed at once (age 0).** The list (`HOSTSEC_APPLY_FASTPATH_PKGS`) covers openssh, libc, sudo, openssl, the kernel, curl, xz and the like. From `-security` it is left to unattended-upgrades, as above |
| Ubuntu `-updates` | `archive.ubuntu.com` | **Held** (`apt-mark hold`) until the box has seen that version for `HOSTSEC_APPLY_GRACE_DAYS` (4), then installed |
| A third-party repo or PPA | `download.docker.com`, `ppa.launchpad.net` | **Held** the same way: this is the real supply-chain surface. A crown-jewel name from such an origin is not fast-tracked; it is held for the full soak and gets a card |
| On your deny-list | any | **Held for good**, with a card: the way to stop one bad version now |

"From Ubuntu" means three things at once: apt trusts the package (its signature checked), its
origin label is `Ubuntu`, `UbuntuESM` or `UbuntuESMApps`, and the site it came from ends in
`.ubuntu.com`. apt's "trusted" alone is true for every signed repo you added, so it is not
enough. If a box pulls Ubuntu from another mirror (a cloud provider's, say), add that host to
`HOSTSEC_APPLY_TRUSTED_SITES` (keep `.ubuntu.com`); until then its Ubuntu updates are held like
a third party's, which is safe, only slower.

The hold is the brake: unattended-upgrades and a manual `apt upgrade` both skip held packages.
Nothing here changes unattended-upgrades' config (apt.conf list options add up across files,
so narrowing its allowed origins is unreliable), and its stock config already installs only
`-security` and ESM. `HOSTSEC_APPLY_BLANKET=1` makes the applier take Ubuntu `-security`
too, with its own soak (`HOSTSEC_APPLY_SECUPDATE_GRACE_DAYS`, 0 by default, so it installs
them at once rather than holding them); that is discouraged.

A `-security` package the applier holds reads as "kept back", so the detector's check 1 never
sees it pending. The detector's backstop (check 5) watches instead: it pages when the applier
has not finished a run for 3 hours, or a hold it set is older than the ceiling
(`HOSTSEC_APPLY_CEILING_DAYS`, 10).

## Running before unattended-upgrades

unattended-upgrades skips every held package. When the daily apt refresh moves a held
`-updates` version into `-security`, the applier releases the hold, but only at its next hourly
run. If unattended-upgrades runs first, the fix waits a whole extra day. So
`install.sh --with-applier` also installs
[`apt-daily-upgrade.nethersec.conf`](../../host/apt-daily-upgrade.nethersec.conf) as
`/etc/systemd/system/apt-daily-upgrade.service.d/nethersec-apply-aged.conf`:

```ini
[Service]
ExecStartPre=-/bin/systemctl start nethersec-apply-aged.service
ExecStartPre=-/bin/sh -c '...wait while nethersec-apply-aged.service is still running (max 30 min)...'
```

unattended-upgrades' unit now starts the applier and waits for it (it is a oneshot) right before
it picks its set, on the same lists. If the hourly run is already going, the start joins it, so
the two never overlap. The second line covers a live applier that upgrades systemd: PID 1
re-executes and cuts `systemctl`'s connection while dpkg still runs, so it polls until the
applier has finished, at most 30 minutes. The leading `-` means a missing, failed or slow applier
never stops unattended-upgrades. The applier's unit must never get `After=`, `Requires=` or
`Wants=` on `apt-daily-upgrade.service`: with `After=` each start would wait on the other for
good. The harness fails if one appears. The file's header has the full reasoning.

## Fail-safe

- **Always exit 0, never silent.** A real failure (the install errored, the pre-install
  simulation failed, dpkg is broken, a package is stuck past the ceiling) **pages**: patching
  has stopped. An advisory (a stale apt cache, an untrusted crown jewel, a failed hold, version
  churn, services still on old code after a library upgrade) is a quiet card. A successful
  install posts a quiet info note. A card that was not delivered (an error answer, no network,
  over the per-run cap) is sent again on the next run, not 6 hours later; the info note is not
  sent again.
- **Fails closed.** Without `python3-apt` it cannot tell origins apart, so it installs
  nothing and sets no new hold (holds it already set stay), and says so. Trust is never
  guessed. `install.sh --with-applier` installs `python3-apt` when it is missing.
- **Stays out of apt's way.** `apt-get -s` takes no lock, and `apt-get update` swaps a changed
  list in by deleting the old file and then renaming the new one. A simulation that reads the
  lists in that gap fails, and that would page for a run that installed nothing. So each run
  first waits (up to `HOSTSEC_APPLY_APT_BUSY_WAIT_SECS`, 600) while apt's own refresh or
  unattended-upgrades is running. A run that still collides with apt is logged with apt's error
  and retried next run without a card; the third in a row (`HOSTSEC_APPLY_COLLIDE_PAGE_RUNS`)
  pages. A run whose lists changed after it sorted the set installs nothing, since the new
  candidate has not soaked. That holds for the third such run too: it pages
  (`apply-apt-collisions`) and still installs nothing.
- **Guarded writes.** The exact set is simulated first and refused if it would remove anything
  or pull in an unexpected new package. A kernel update may newly install
  `linux-image-*`, `linux-headers-*`, `linux-modules-*`, `linux-modules-extra-*` and
  `linux-main-modules-*` (Ubuntu 26.04 splits ZFS out that way); each entry is a no-soak
  exception, so the list holds only families seen pulled in by a kernel meta.
  `HOSTSEC_APPLY_KERNEL_NEWINSTALL_GLOBS` replaces it per box (include the defaults).
- **Holds are written down first**, then set, and only holds it wrote down are ever released.
  A hold you set yourself is left alone. A release that fails (another apt holding the lock)
  stays on the list and is tried again every run, with an `apply-unhold-failed-<pkg>` card, so
  a hold never ends up with nobody tracking it.
- **The kill switch fails toward patched.** `/etc/nethersec/apply-disabled` (or the shared
  `/etc/nethersec/disabled`, or `HOSTSEC_APPLY_ENABLED=0`) releases every hold it set and
  stops all writes. A hold with nothing to manage it is the worst silent-unpatched state. To
  stop one bad version, use the deny-list, not the kill switch.

## Three kinds of "pending"

During an incident these can each answer "is this box patched?" differently:

1. The **detector's** `first-seen.security-updates.tsv`: a clock per package name over the
   `-security` pocket. It drives the "Security updates stuck" card.
2. The **applier's** `first-seen.apply.tsv`: a soak clock per `package=version=arch`, kept
   for every upgradable package and used for the held pockets, plus `episode.apply.tsv`, a
   clock per name that a new version cannot reset, which drives the ceiling page.
3. **apt's phased updates**: Ubuntu holds some `-updates` back per machine. The applier reads
   candidates through `python3-apt`, so a phased-back package is simply not a candidate yet.

## Install and operate

```sh
sudo bash host/install.sh --with-applier                          # adds it, dry-run
sudo systemctl start nethersec-apply-aged.service                 # one dry run now
journalctl -u nethersec-apply-aged.service -n 40 --no-pager       # the would-install set
# go live: set HOSTSEC_APPLY_DRYRUN=0 in /etc/nethersec/apply.env
echo 'somepkg=1.2.3-1' | sudo tee -a /etc/nethersec/apply-denylist   # hold one version for good
sudo touch /etc/nethersec/apply-disabled                          # pause; releases its holds on the next run
```

`--with-applier` also turns on Docker live-restore where Docker is installed (see
[mitigations.md](mitigations.md)): a live applier installs Docker and containerd upgrades, and
without live-restore each one restarts every container.

Disabling the timer alone is not a pause: the drop-in still starts the applier before
unattended-upgrades every day. Use `apply-disabled`, which also covers that daily run.
`sudo bash host/install.sh --uninstall` releases the holds first, then removes the timer, the
unit and the drop-in. The state in `/var/lib/nethersec` is disposable.

The tuning knobs are in [apply.env.example](../../host/apply.env.example), except
`HOSTSEC_APPLY_CHURN_COUNT` (6): the number of versions in one episode that raises the churn
card.
