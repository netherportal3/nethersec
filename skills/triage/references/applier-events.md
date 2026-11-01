# Release-age applier events

Sent by `/opt/nethersec/apply-aged-upgrades.sh` (hourly, and right before unattended-upgrades),
`kind: security`. Design: `docs/host/applier.md`.

Two things differ from the detector:

- **The applier never sends `resolved`.** Its cards stay open until a person presses Resolve.
  Confirm the cause is gone (a clean run in the journal), then Resolve.
- A card is sent again at most every 6 hours (`HOSTSEC_APPLY_RESURFACE_SECS`) while the cause
  stays, or at once if its severity changes. One that was not delivered goes again on the next
  run.

In the `-<pkg>` events, `<pkg>` is the package name with each character other than a-z and 0-9
turned into `-` (`linux-image-6.8.0-49-generic` becomes `linux-image-6-8-0-49-generic`).

Read the last runs first:

```sh
journalctl -u nethersec-apply-aged.service -n 80 --no-pager
sudo sh /opt/nethersec/nethersec-status.sh --json      # .applier: dry_run, heartbeat, holds
sudo cat /var/lib/nethersec/holds.apply.tsv             # holds the applier set: name, version, reason, since
```

Journal lines worth knowing: `DRYRUN: would apply: <set>`, `applied: <set>`,
`nothing to apply this run`, `lockstep: co-applying ...`, `waiting up to ...s: <why>`,
`apt collision N in a row, no card, retrying next run`.

## Pages (critical): patching has stopped

| Event | Means | Confirm | Fix |
|---|---|---|---|
| `apply-failed` | `apt-get install --only-upgrade` failed. The card has apt's error and the set. | The journal; `sudo dpkg --audit` | Read apt's error. If dpkg was left half-done, `sudo dpkg --configure -a` (ask). The next run retries. |
| `apply-sim-failed` | The simulation of the aged-in set failed, so nothing was applied. | Run it by hand: `sudo apt-get -s install --only-upgrade <set from the card>` | Usually a held or missing dependency. Fix that, or deny-list the package. |
| `apply-dpkg-broken` | `dpkg --audit` reports problems, so the applier stands down. | `sudo dpkg --audit` | `sudo dpkg --configure -a` (ask), then check `dpkg --audit` is empty. |
| `apply-stuck-<pkg>` | A gated package has been pending past the ceiling (10 days) without being applied. | `apt-cache policy <pkg>`; `sudo apt-get -s install --only-upgrade <pkg>` | Find why it never ages in or never installs (a held dependency, version churn, a refused simulation). |
| `apply-apt-collisions` | The third run in a row stood down on apt's own runs, and this one's lists changed after it sorted the set, so it installed nothing (the new candidates have not soaked). The card has the reason and the set. | `systemctl list-timers 'apt-daily*' --no-pager`; `journalctl -u apt-daily.service -u unattended-upgrades.service -n 50 --no-pager`; the applier journal | Find what keeps apt busy or refreshing its lists at the applier's time (a stuck apt-daily, a cron job running `apt-get update`). Nothing installs until a run gets settled lists. |

A run that collides with apt's own refresh or unattended-upgrades is retried without a card.
From the third collision in a row (`HOSTSEC_APPLY_COLLIDE_PAGE_RUNS`) it is handled as a real
failure, so a step that keeps failing pages. A run whose lists changed after it sorted the set
never installs: the third such run pages `apply-apt-collisions` instead.

## Quiet cards (warning)

| Event | Means | Confirm | Fix |
|---|---|---|---|
| `apply-stale-cache` | apt's lists are old (48h) and apt's own success stamp is old or missing too, so release ages cannot be trusted. Applied nothing. | `ls -l /var/lib/apt/periodic/update-success-stamp`; `systemctl status apt-daily.timer apt-daily.service --no-pager`; `journalctl -u apt-daily.service -n 30 --no-pager` | Fix apt-daily (network, a broken source list). Old list files alone are normal in a quiet week; the stamp is what counts. |
| `apply-introspect-unavailable` | It cannot read apt origins (`python3-apt` missing or the cache unreadable), so it applies and holds nothing. Existing holds stay. | `python3 -c 'import apt'` | `sudo apt-get install python3-apt` (ask). |
| `apply-hold-failed-<pkg>` | `apt-mark hold` failed for a package it meant to hold. | `apt-mark showhold`; the journal | Usually apt busy; it retries every run. |
| `apply-unhold-failed-<pkg>` | `apt-mark unhold` failed, so the package stays held and none of its updates install, security fixes included. The applier keeps it on its list and retries every run. | `apt-mark showhold`; the journal; `sudo lsof /var/lib/dpkg/lock-frontend` | Find what holds apt's lock (another apt, cloud-init, a config tool). If it persists, `sudo apt-mark unhold <pkg>` (ask). |
| `apply-anom-<pkg>` | A crown-jewel package (openssl, libc, the kernel, ...) is offered by a repo that is not Ubuntu's own. Not fast-tracked: held for the full soak. | `apt-cache policy <pkg>`; `grep -r . /etc/apt/sources.list /etc/apt/sources.list.d/` | Check the repo is legitimate. A cloud provider's Ubuntu mirror goes in `HOSTSEC_APPLY_TRUSTED_SITES` (keep `.ubuntu.com`). An unknown repo shadowing a core package is an incident. |
| `apply-deny-<pkg>` | The package is on `/etc/nethersec/apply-denylist`, so it is held for good. | `sudo cat /etc/nethersec/apply-denylist` | Expected while denied. Take it off the list when a good version is out. |
| `apply-churn-<pkg>` | The package published many versions (6) in one soak episode without ever aging in. | `apt-cache policy <pkg>`; the repo's changelog | Could be a flood of releases to dodge the soak. Investigate the origin; deny-list if in doubt. |
| `apply-would-remove` | The aged-in set would remove packages, so it was refused. | The card names them; `sudo apt-get -s install --only-upgrade <set>` | Decide by hand with the person. The applier never removes. |
| `apply-unexpected-newinstall` | The aged-in set would newly install a package that has not soaked. Refused. | The card names it | A kernel family not on the list (a new Ubuntu release): add it to `HOSTSEC_APPLY_KERNEL_NEWINSTALL_GLOBS` in `apply.env`, keeping the defaults. Anything else: wait for it to soak. |
| `apply-needrestart` | Libraries were upgraded but services still run the old code. Applied is not protected yet. | `sudo needrestart -b` | Restart the named services or reboot (ask; see "Reboot one box" in [host-events.md](host-events.md)). |

## Info note (no card)

`apply-applied` "Updates applied": a live run installed packages. Nothing to resolve. Expect
`reboot-pending` data or an `apply-needrestart` card after a library or kernel upgrade.

## The levers

- **Stop one bad version now:** add it to the deny-list, `pkg=version` for one version or the
  bare name for every version:
  ```sh
  echo 'somepkg=1.2.3-1' | sudo tee -a /etc/nethersec/apply-denylist
  ```
- **Stop applying, keep holding:** set `HOSTSEC_APPLY_DRYRUN=1` in `/etc/nethersec/apply.env`.
- **Stop the applier entirely:** `sudo touch /etc/nethersec/apply-disabled`, then
  `sudo systemctl start nethersec-apply-aged.service` to release every hold it set now.

Disabling only the timer is not a pause: unattended-upgrades still starts the applier every day
through its drop-in. Turning the applier off releases its holds on purpose, so packages do not
stay frozen with nobody watching them.
