---
name: go-live
description: Arm the parts of nethersec that act, one box at a time, after watching them in dry-run. The release-age applier (HOSTSEC_APPLY_DRYRUN=0, so aged-in apt upgrades install by themselves) and the flood detector's blocking (HOSTSEC_FLOOD_MITIGATE=1, self-expiring nftables drops of one dominant attacker address). Covers the evidence to collect first, the person's go, the exact switch, the first live run, and every rollback command. Use when someone says "turn on the applier", "take the applier out of dry-run", "go live", "arm flood mitigation", "enable auto-blocking", "start auto-patching", or asks how to undo either.
---

# Go live: arm the applier or the flood blocking

Both ship dark on purpose. Arm one part on one box, watch it, then the next box. The docs say
neither has run on a live server as packaged here (`docs/host/applier.md`, `docs/host/flood.md`):
the first boxes you arm are the real test, so pick ones where a mistake is cheap.

## Rules

- **Ask before arming.** Show the person the evidence below and the rollback, and get a clear
  yes for this box. A yes for one box is not a yes for the next.
- **One box at a time.** Least critical first. A box whose downtime hurts most goes last, in a
  window the person picks.
- **Rollback ready before the switch.** Know the exact command (below) and that you can reach
  the box another way if the network part goes wrong.
- **Not read is not fine.** No journal for the dry-run period means no evidence. Collect it.
- No secret on a command line. These two env files hold no secret, but `report.env` does:
  never print it.

## Part 1: the release-age applier

### Evidence first (read-only)

```sh
sudo sh /opt/nethersec/nethersec-status.sh --json      # .applier: installed, enabled, dry_run true, heartbeat recent
journalctl -u nethersec-apply-aged.service --since -7d --no-pager | grep -E 'DRYRUN|nothing to apply|refused|failed|lockstep|collision' | tail -n 40
sudo cat /var/lib/nethersec/holds.apply.tsv
systemctl show apt-daily-upgrade.service -p DropInPaths  # includes nethersec-apply-aged.conf
sudo bash /opt/nethersec/docker-live-restore.sh --check; echo "live-restore rc=$?"   # 0 on, 1 off or no answer, 2 no Docker
```

Ready when all of these hold:

- [ ] It ran in dry-run for at least one soak window (`HOSTSEC_APPLY_GRACE_DAYS`, 4 days by
  default) and the journal shows `DRYRUN: would apply: ...` sets the person agrees with.
- [ ] No applier card is open for this box (none of the pages in the `triage` skill's
  `references/applier-events.md`), and `apply-backstop` is not raised.
- [ ] On a Docker box, live-restore is on (rc 0). Without it, a Docker or containerd upgrade
  restarts every container.
- [ ] The person knows the first live run installs the whole aged-in backlog at once, and picked
  when. A database or anything clients reach by Docker service name: Docker's embedded DNS does
  not answer while dockerd restarts, so either do Docker upgrades in a window, or hold those
  packages on that box.

### Arm it

```sh
sudo sed -i 's/^HOSTSEC_APPLY_DRYRUN=.*/HOSTSEC_APPLY_DRYRUN=0/' /etc/nethersec/apply.env
sudo grep '^HOSTSEC_APPLY_DRYRUN=' /etc/nethersec/apply.env     # HOSTSEC_APPLY_DRYRUN=0
sudo systemctl start nethersec-apply-aged.service               # the first live run, now, while you watch
journalctl -u nethersec-apply-aged.service -n 60 --no-pager
```

If the `grep` prints nothing, the file had no uncommented `HOSTSEC_APPLY_DRYRUN` line: add
`HOSTSEC_APPLY_DRYRUN=0` yourself (the default without it is dry-run). The unit reads
`apply.env` at every start; no reload is needed. Look for `applied: <set>` and an "Updates
applied" note in `#nethersec-status`, or `nothing to apply this run`.

If `systemctl start` comes back with an error while dpkg is still working, an upgrade of
systemd may have restarted PID 1 and cut the connection. Wait for the unit to finish, then:

```sh
systemctl is-active nethersec-apply-aged.service     # wait until: inactive (or failed)
sudo dpkg --audit                                    # want: no output
```

### After the first live run

- `sudo needrestart -b`: services still on old code. An `apply-needrestart` card says the same.
  Restarting them or rebooting is a separate ask.
- `sudo systemctl start nethersec-security-report.service`, then the status JSON: nothing new
  raised, `applier.dry_run: false`.
- Watch the next few days of journal and cards before arming the next box.

### Roll back

```sh
# Stop installing, keep the soak holds (back to dry-run):
sudo sed -i 's/^HOSTSEC_APPLY_DRYRUN=.*/HOSTSEC_APPLY_DRYRUN=1/' /etc/nethersec/apply.env
# Stop one bad version (pkg=version, or the bare name for every version):
echo 'somepkg=1.2.3-1' | sudo tee -a /etc/nethersec/apply-denylist
# Stop the applier and release every hold it set, now:
sudo touch /etc/nethersec/apply-disabled && sudo systemctl start nethersec-apply-aged.service
# Remove all of nethersec from the box (from the clone; releases holds first):
sudo bash host/install.sh --uninstall
```

Disabling the timer alone is not a pause: unattended-upgrades starts the applier daily through
its drop-in. Undoing an upgrade that already installed is ordinary apt work
(`sudo apt-get install somepkg=<old version>`, when apt still has that version); nethersec does
not do it for you.

## Part 2: flood blocking

### Evidence first (read-only)

```sh
sudo sh /opt/nethersec/nethersec-status.sh --json      # .flood: installed true, mitigate false
journalctl -u nethersec-flood-report.service --since -7d --no-pager | grep -E 'DRY-RUN|would' | tail -n 40
sudo grep -vE '^[[:space:]]*(#|$)' /etc/nethersec/flood.env
```

Ready when all of these hold:

- [ ] Detection ran through a normal week, peaks included, with thresholds tuned so it did not
  fire on real traffic.
- [ ] Every `would nft-drop <ip>` in the journal was a real attacker, never your own address, a
  monitor, a partner, or a proxy in front of the box.
- [ ] `HOSTSEC_FLOOD_ALLOW_IPS` lists your admin address, uptime monitors, your own servers that
  talk to this box, and any load balancer or proxy in front of it. It matches exact addresses,
  not ranges. Only Cloudflare's ranges and part of Fastly's are spared by themselves: behind any
  other proxy, every request seems to come from the proxy, and dropping it takes the site down.
- [ ] The box does not run docker-mailserver (its own in-container fail2ban manages nftables; a
  host drop would collide). Detection still works there.
- [ ] The person knows how it acts: at most `HOSTSEC_FLOOD_MITIGATE_MAX_PER_HOUR` (6) drops an
  hour, each expiring after `HOSTSEC_FLOOD_MITIGATE_MINUTES` (60), IPv4 only, one dominant
  source of an established-connection flood or an HTTP flood. Past the cap it only alerts.

### Arm it

```sh
sudo sed -i '/^HOSTSEC_FLOOD_MITIGATE=/d' /etc/nethersec/flood.env
echo 'HOSTSEC_FLOOD_MITIGATE=1' | sudo tee -a /etc/nethersec/flood.env
sudo stat -c '%a %U' /etc/nethersec/flood.env           # want: 600 root
sudo sh /opt/nethersec/nethersec-status.sh --json       # .flood.mitigate true
```

It takes effect on the next run (every minute). The table `inet nethersec_flood` appears only
with the first drop: `sudo nft list table inet nethersec_flood`. A drop shows on the card as
`[auto-dropped <ip> for 60m; ...]`.

### Roll back

Turn it off first, then clear, or the next run can drop again:

```sh
sudo sed -i 's/^HOSTSEC_FLOOD_MITIGATE=.*/HOSTSEC_FLOOD_MITIGATE=0/' /etc/nethersec/flood.env
sudo sh /opt/nethersec/flood-report.sh --unmitigate              # removes every drop (the whole table)
sudo sh /opt/nethersec/flood-report.sh --unmitigate-ip 203.0.113.9   # or just one address
```

`sudo touch /etc/nethersec/flood-disabled` pauses detection too. A wrong drop: remove it, add
the address to `HOSTSEC_FLOOD_ALLOW_IPS`, and tell the person.

## Done when

- [ ] The person said yes for this box, with the evidence in front of them.
- [ ] The first live run (applier) or the armed state (flood) is verified as above.
- [ ] The rollback commands are written down where the person will find them.
- [ ] You watched it for a while before the next box.
