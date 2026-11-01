# Host detector and flood detector events

Every event below is `kind: security`, sent by `/opt/nethersec/security-report.sh` (every
30 minutes) or `/opt/nethersec/flood-report.sh` (every minute). A raised check is sent once,
then again at most every 6 hours (flood: every hour) while it stays raised. When it clears, the
box sends `resolved`: the card says "The box reports this is fixed" and waits for a person. A
report the hub did not take (an error answer, no network, over the per-run cap) is sent again on
the next run.

Commands run on the box. All confirm commands are read-only.

## Detector checks

### `security-updates`: "Security updates stuck"

- **Means:** a `-security` update has been pending past its own window (26 hours from when that
  package was first seen). **Critical (page)** when a stuck one fixes a High or Critical Ubuntu
  CVE. **Warning** when none of the stuck ones is High or Critical: unattended-upgrades looks
  stopped. A stuck one whose grade cannot be looked up goes into `monitor-unreadable` instead.
  With `HOSTSEC_CVE_LOOKUP=0` a stuck update is always a warning.
- **Confirm:**
  ```sh
  apt-get -s dist-upgrade | grep '^Inst' | grep -- '-security'
  sudo awk -F'\t' '{print $1, $3, $5, $6}' /var/lib/nethersec/first-seen.security-updates.tsv
  systemctl status unattended-upgrades.service apt-daily-upgrade.timer --no-pager
  sudo tail -n 40 /var/log/unattended-upgrades/unattended-upgrades.log
  sudo grep -i 'held back' /var/log/unattended-upgrades/unattended-upgrades.log | tail -n 5
  apt-mark showhold; sudo dpkg --audit
  ```
  The `.tsv` columns shown are package, candidate version, CVE priority, CVE.
- **Fix:** find why unattended-upgrades skipped it (a hold, a broken dpkg, a stopped timer, a
  failed run in its log). Holds the applier set are in `/var/lib/nethersec/holds.apply.tsv`;
  any other hold is someone's choice, so ask. To apply the security set now, the same way the
  daily run does: `sudo unattended-upgrade -v` (ask first; it installs packages).
- **Resolve:** after the next detector run reports it fixed and the simulation above lists
  nothing.
- `security-updates-applied` is the matching **info note** when a batch with a High or Critical
  fix cleared. No card, nothing to do.

### `reboot-security`: "Reboot needed for a security fix"

- **Means:** a staged update needs a reboot (or a service restart) and fixes a High or Critical
  CVE that is not live yet. Warning, never a page. Staged updates that are low, medium or already
  live go only into the weekly pending-reboot summary (`reboot-pending` data, no card). A newer
  kernel whose CVEs still cannot be looked up 3 days after its install
  (`HOSTSEC_REBOOT_UNGRADED_SECS`) is carded too.
- **Confirm:**
  ```sh
  cat /var/run/reboot-required.pkgs 2>/dev/null; uname -r; ls /boot/vmlinuz-*
  /snap/bin/canonical-livepatch status --verbose 2>/dev/null | head -n 40
  sudo needrestart -b
  ```
  A kernel CVE is live when Livepatch is applied to the running kernel and lists it. Any other
  package is live when `needrestart -b` names no service still on old code.
- **Fix:** restart the services `needrestart -b` names (`NEEDRESTART-SVC` lines), or reboot.
  Both interrupt service: ask, and follow "Reboot one box" below.
- **Resolve:** after the box reports it fixed (it sends `resolved` once the CVEs are live or the
  box rebooted).

### `ssh-auth-burst`: "SSH auth burst"

- **Means:** failed SSH logins since the last run crossed `HOSTSEC_SSH_BURST` (default 2000).
  Warning by default. On a box that takes keys only, this is scanning noise.
- **Confirm:**
  ```sh
  sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication) '
  journalctl -u ssh --since -1d --no-pager | grep -E 'Accepted (publickey|password|keyboard-interactive)' | tail -n 20
  sudo fail2ban-client status sshd 2>/dev/null
  ```
- **Fix:** keys only (see `ssh-password-auth`), fail2ban, or a firewall rule for SSH (ask). An
  `Accepted` line from an address or user you do not know is an incident: stop, tell the person,
  change nothing yet, keep the logs.
- **Resolve:** when the box reports the burst is over.

### `log-error-rate`: "Application error-log burst"

- **Means:** error lines per hour in journald (`-p err`, minus sshd) and container logs crossed
  `HOSTSEC_LOGERR_BURST` (default 600). Warning by default.
- **Confirm:**
  ```sh
  journalctl -p err --since -1h --no-pager | grep -v sshd | tail -n 40
  for c in $(docker ps --format '{{.Names}}'); do printf '%s %s\n' "$c" "$(docker logs --since 1h "$c" 2>&1 | grep -ciwE 'error|fatal|panic')"; done
  ```
- **Fix:** the noisy service. If it is known noise, add a pattern to `HOSTSEC_LOGERR_EXCLUDE_RE`
  or raise `HOSTSEC_LOGERR_BURST` in `report.env` after watching the box's normal level.
- **Resolve:** when the box reports it fixed.

### `apply-backstop`: "Release-age applier backstop"

- **Means:** **critical (page).** The applier has not finished a run for 3 hours, or a hold it
  set is older than its ceiling (10 days). Packages it manages may be going unpatched. Silent
  while `/etc/nethersec/apply-disabled` exists.
- **Confirm:**
  ```sh
  systemctl status nethersec-apply-aged.timer nethersec-apply-aged.service --no-pager
  journalctl -u nethersec-apply-aged.service -n 60 --no-pager
  date -d "@$(sudo cat /var/lib/nethersec/apply-heartbeat)"
  sudo cat /var/lib/nethersec/holds.apply.tsv
  ```
- **Fix:** whatever stops the run (a disabled timer, apt stuck, a failing unit), or for a stuck
  hold see `apply-stuck-<pkg>` in [applier-events.md](applier-events.md). Disabling the timer is
  not a pause; `apply-disabled` is.
- **Resolve:** after a clean applier run and the box reports it fixed.

### `script-path-writable`: "Security scripts on a world-writable path"

- **Means:** a directory on the path to the root-run scripts (one without the sticky bit), or a
  script, is writable by any local user. Someone could swap a script before the next root run.
  Warning.
- **Confirm:** the card names the paths. From the clone: `bash host/install.sh --check-path`.
  Check the installed scripts were not changed (clone at the commit in `/opt/nethersec/VERSION`):
  ```sh
  cd ~/nethersec/host && for f in *.sh *.py; do cmp -s "$f" "/opt/nethersec/$f" || echo "differs: $f"; done
  ```
- **Fix:** `sudo chmod o-w <path>` (ask), find who changed it, then re-run
  `sudo bash host/install.sh` from a clean clone. A script that differs is an incident.
- **Resolve:** when the box reports it fixed and nothing differs.

### `thirdparty-updates`: "Vendor package updates not installed"

- **Means:** a package from a non-distro apt repo (Docker, a runtime vendor, a VPN client) has
  had a newer version for 7 days. Nothing else installs those unless the applier is live.
  Warning.
- **Confirm:** `apt list --upgradable 2>/dev/null`, then `apt-cache policy <pkg>`.
- **Fix:** upgrade it with the person's yes (`sudo apt-get install --only-upgrade <pkg>`; a Docker
  or containerd upgrade restarts dockerd, so check `docker-live-restore.sh --check` first), let a
  live applier do it, or skip a package on purpose with `HOSTSEC_THIRDPARTY_IGNORE`.
- **Resolve:** when the box reports it fixed.

### `docker-live-restore`: "Docker live-restore off"

- **Means:** a Docker or containerd restart would stop every container. Warning.
- **Confirm:** `sudo bash /opt/nethersec/docker-live-restore.sh --check` (0 on, 1 off or Docker
  not answering, 2 no Docker).
- **Fix:** `sudo bash /opt/nethersec/docker-live-restore.sh` (SIGHUP reload, restarts no
  container, refuses on a swarm node). Ask first.
- **Resolve:** when the box reports it fixed.

### `livepatch-off`: "Livepatch not running"

- **Means:** the Livepatch client is missing, not enabled, or does not support or cannot patch
  the running kernel, so kernel fixes wait for a reboot. Warning. On by default on Ubuntu.
- **Confirm:** `/snap/bin/canonical-livepatch status` (or `canonical-livepatch status`).
- **Fix:** needs an Ubuntu Pro account, so the person does it. The card suggests the route with
  no token on the command line: `sudo pro attach` with no token (it shows a code to confirm in a
  browser; on a box that is attached already it only says so), then `sudo pro enable livepatch`,
  which installs the client if needed. Never paste a token into a command. Known gap: the Pro
  client then starts `canonical-livepatch enable` with a token for this box as an argument, so
  other local users could read it in the process list for a moment; say so and let them choose
  when. An unsupported kernel needs a reboot into a supported one. To stop checking on purpose:
  `HOSTSEC_LIVEPATCH_CHECK=0`.
- **Resolve:** when the box reports it fixed.

### `ipv4-options-drop-off`: "IP-options drop off"

- **Means:** the nftables table that drops IPv4 TCP packets with IP options (the CVE-2026-98432
  trigger) is not loaded, or its boot unit is not enabled. Warning. On by default on Ubuntu.
- **Confirm:** `sudo bash /opt/nethersec/ipv4-options-drop.sh --check`.
- **Fix:** `sudo bash /opt/nethersec/ipv4-options-drop.sh` (ask; restarts nothing). If it was on
  before, find out what removed it (`systemctl status nethersec-ipv4-options-drop.service`;
  another tool that flushes the whole nftables ruleset).
- **Resolve:** when the box reports it fixed.

### `ssh-password-auth`: "SSH accepts passwords"

- **Means:** `sshd -T` shows password logins on (or keyboard-interactive with PAM). Warning.
- **Confirm:**
  ```sh
  sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|usepam) '
  sudo grep -ri -e passwordauthentication -e kbdinteractive /etc/ssh/sshd_config.d /etc/ssh/sshd_config
  ```
- **Fix (SSH change, ask first):** prove key login works for every account that needs it. Keep
  the current session open. sshd keeps the first value it reads and reads `sshd_config.d` in name
  order first, so an early file wins:
  ```sh
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' | sudo tee /etc/ssh/sshd_config.d/00-keys-only.conf
  sudo sshd -t && sudo systemctl reload ssh
  ```
  Open a new connection with the pinned key before closing the old one. Rollback: remove that
  file and reload.
- **Resolve:** when the box reports it fixed.

### `unexpected-listener`: "Unexpected listener"

- **Means:** a TCP or UDP socket on a non-loopback address is not in `HOSTSEC_LISTEN_ALLOW`.
  Warning. Off until the allowlist is set. A new set of listeners re-posts at once.
- **Confirm:** the card names the sockets. `sudo ss -Htulnp` shows the process.
- **Fix:** a service you meant to add: take a new snapshot (`firewall-snapshot.sh`) and replace
  the allowlist line, keeping the file mode 600:
  ```sh
  sudo sed -i '/^HOSTSEC_LISTEN_ALLOW=/d' /etc/nethersec/report.env
  sudo sh -c 'bash /opt/nethersec/firewall-snapshot.sh | grep "^HOSTSEC_LISTEN_ALLOW=" >> /etc/nethersec/report.env'
  sudo stat -c '%a %U' /etc/nethersec/report.env     # want: 600 root
  ```
  Something nobody can explain is a possible compromise: do not kill it yet, tell the person,
  and keep evidence (`sudo ls -l /proc/<pid>/exe`, `sudo tr '\0' ' ' < /proc/<pid>/cmdline`).
- **Resolve:** when the box reports it fixed and every listener is explained.

### `monitor-unreadable`: "Host security monitor unreadable"

- **Means:** one or more checks could not read this run, so their signal is unknown, not clear.
  Warning. The detail names them. It resolves only when every check reads again.
- **Confirm:** `sudo sh /opt/nethersec/nethersec-status.sh --json` (the `unreadable` list) and
  `journalctl -u nethersec-security-report.service -n 60 --no-pager`.

  | Name in the detail | What could not read | Usual cause |
  |---|---|---|
  | `security-updates` | `apt-get -s dist-upgrade`, the clock, or the CVE grade of a stuck update | apt busy or broken; no way out to `ubuntu.com` (then consider `HOSTSEC_CVE_LOOKUP=0`) |
  | `ssh-auth`, `log-errors` | journald, container logs | journald or Docker not answering |
  | `thirdparty-updates` | the apt cache through `apt-introspect.py` | `python3-apt` missing |
  | `docker-live-restore` | `docker info` | dockerd down |
  | `livepatch` | the Livepatch client | snap not answering |
  | `ipv4-options-drop` | `ipv4-options-drop.sh --check` | `nft` not answering |
  | `sshd` | `sshd -T` | broken sshd config |
  | `listeners` | `ss` | iproute2 missing |
  | `container-packages` | `docker ps` (the list of containers) | dockerd down |

- **Fix:** the reader, not the card. A one-run apt lock during unattended-upgrades clears on the
  next run by itself. Never treat what it covers as fine meanwhile.
- **Resolve:** after the box reports every check reads again.

### Data events (no card)

`reboot-pending` and `container-packages` are stored by the hub, never carded by themselves.
They feed the weekly pending-reboot summary (`/nethersec reboots`) and the container check. A
`selftest` card or note is one you sent by hand.

## Flood detector checks

Detection only unless `HOSTSEC_FLOOD_MITIGATE=1` (see the `go-live` skill). Warning by default;
`HOSTSEC_FLOOD_<CHECK>_SEVERITY=critical` makes one page. The card detail says what the drop
would have done: `[would drop <ip> ...; mitigation DARK/dry-run]`, `[auto-dropped <ip> ...]`, or
why it was skipped (protected CDN range, allowlisted, hourly cap, IPv6).

- **`conn-flood`** "Connection flood": conntrack nearly full, a SYN-recv burst, or one non-CDN
  source holding most established connections. Confirm:
  ```sh
  ss -s
  cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max
  ss -Htn state established | awk '{print $4}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head
  ```
- **`net-flood`** "Inbound network flood": packets or bits a second over the threshold. No
  single source, so never blocked. Confirm: `cat /proc/net/dev` twice a few seconds apart, and
  your provider's traffic graphs.
- **`http-flood`** "HTTP request flood": one client sends most requests in the Caddy JSON access
  log. Confirm: `docker logs --since 5m <caddy container> 2>&1 | tail -n 50`.
- **`smtp-flood`** "SMTP connect flood": a burst of postfix `connect from` lines in the mail
  container. Confirm: `docker logs --since 10m <mail container> 2>&1 | grep -c 'connect from'`.
- **`monitor-unreadable-flood`** "Flood monitor unreadable": a signal exists on the box but could
  not be read (conntrack, `ss`, Docker, `python3`). Confirm:
  `journalctl -u nethersec-flood-report.service -n 40 --no-pager`.

- **Fix:** decide with the person whether it is an attack or real traffic (a launch, a crawler
  wave, a backup). Blocking by hand is a firewall change: ask. A wrong automatic drop is undone
  with `sudo sh /opt/nethersec/flood-report.sh --unmitigate-ip <ip>`, all of them with
  `--unmitigate`.
- **Tune:** raise thresholds in `/etc/nethersec/flood.env` for real traffic. Keep tuned values
  private.
- **Resolve:** when the box reports the flood is over.

## Reboot one box

Only with the person's yes, one box at a time:

1. Read the state: `uptime -s`, `docker ps`, `sudo dpkg --audit` (want empty), no apt run in
   progress (`systemctl is-active apt-daily-upgrade.service unattended-upgrades.service`), and
   that the old kernel is still installed for rollback (`ls /boot/vmlinuz-*`).
2. Schedule the reboot so it outlives your SSH session: `sudo systemd-run --on-active=5s systemctl reboot`.
3. Wait, then reconnect with the same pinned key until `uptime -s` changes. Do not hammer it.
4. Check: `uname -r`, `docker ps`, the box's own health checks, then
   `sudo systemctl start nethersec-security-report.service` and the status JSON.
5. Only then the next box.
