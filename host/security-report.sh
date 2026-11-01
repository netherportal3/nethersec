#!/usr/bin/env sh
# security-report.sh: the read-only host security detector.
#
# A systemd timer (nethersec-security-report.timer) runs it every 30 minutes. Each run
# evaluates the checks below and reports through nethersec-report.sh with `--kind
# security`, only when a check changes state. Without --severity a report is a quiet
# card; `critical` pages. A `resolved` report tells the hub the box thinks it is fixed;
# the hub keeps a security card open until a person resolves it, so a box that was
# taken over cannot quietly clear its own alert.
#
# Checks (each posts on a STATE TRANSITION, not every run):
#   1. Pending security updates: event `security-updates`. SILENT while an update is
#      merely pending / auto-applying (within HOSTSEC_SECUPDATE_GRACE_SECS, default
#      26h, timed PER PACKAGE from when that package was first seen pending), so a
#      routine same-day unattended-upgrade never cards. When the episode (the pending
#      set) clears, a one-shot QUIET "done" note fires (`security-updates-applied`,
#      info, no page), but only if the batch fixed a High/Critical CVE. A package
#      still pending PAST its own grace (auto-upgrade failed to apply it = STUCK) pages
#      (critical) ONLY if it fixes a High/Critical Ubuntu CVE (resolved via
#      cve-severity.py); stuck packages that are only low/medium instead raise ONE
#      quiet, non-paging card (unattended-upgrades looks stopped), and an
#      UNDETERMINABLE severity folds into `monitor-unreadable` (a stuck update is never
#      dropped, but never a false page).
#   2. Reboot pending: event `reboot-security`, a quiet card (warning, no ping) ONLY
#      when a staged update that needs the reboot fixes a High/Critical CVE that is not
#      live yet. A kernel CVE is live when Livepatch has applied it to the running
#      kernel; a CVE in any other package (libc6, dbus, systemd...) is live when
#      needrestart says no service still runs the old code. Everything else (low/medium
#      fixes, High/Critical ones already live) is no card: it goes into the hub's weekly
#      summary, fed by a `reboot-pending` data report (info) the hub stores and never
#      turns into a card. A lookup that cannot finish makes no card and marks the box
#      "not checked" in that summary.
#   3. SSH auth burst: event `ssh-auth-burst`. Warning (quiet) by default when failed
#      SSH logins since the last run cross a threshold, which turns silent fail2ban
#      banning into a card. Quiet, not a page, by default: on a box that takes keys
#      only, a burst is scanning noise, not a brute force that can land. Set
#      HOSTSEC_SSH_SEVERITY=critical on any box where password auth is enabled.
#   4. Log error-rate: event `log-error-rate`. Warning (quiet) by default when the
#      errors/hour across journald (priority err, minus the SSH scanner noise check 3
#      owns) + docker container logs cross a threshold. Quiet with a HIGH threshold on
#      purpose: app/container error logs are a noisier signal than SSH auth, so a low
#      or `critical` default would page all day. Baseline each box, then lower it.
#   5. Applier backstop: event `apply-backstop`. Pages when the release-age applier has
#      not completed a run for 3h, or a hold it set is older than its ceiling.
#   6. Writable script path: event `script-path-writable`. Warning (quiet) when a
#      directory on the path to these root-run scripts (up to /) is world-writable
#      without the sticky bit, or one of the scripts is: any local user could swap a
#      script in before the next root run.
#   7. Vendor package updates not installed: event `thirdparty-updates`. Warning
#      (quiet), one card per box, when a package from a non-distro apt repo (Docker's
#      or another vendor's) has had a newer version for longer than
#      HOSTSEC_THIRDPARTY_GRACE_SECS (default 7 days). Nothing else installs those:
#      unattended-upgrades takes distro origins only, and the applier ships in dry-run.
#   8. Docker live-restore off: event `docker-live-restore`. Warning (quiet) when
#      Docker is installed and its daemon reports live-restore off, so a Docker or
#      containerd upgrade or restart would stop every container on the box. Inert where
#      Docker is not installed. docker-live-restore.sh turns it on.
#   9. Livepatch not running: event `livepatch-off`. Warning (quiet) when the Livepatch
#      client is missing or not enabled, or says it does not support or could not patch
#      the running kernel, so kernel fixes wait for a reboot. On by default on Ubuntu.
#  10. IP-options drop off: event `ipv4-options-drop-off`. Warning (quiet) when
#      `ipv4-options-drop.sh --check` says its nftables table is not loaded or its boot
#      unit is not enabled (the CVE-2026-98432 mitigation). On by default on Ubuntu.
#  11. SSH accepts passwords: event `ssh-password-auth`. Warning (quiet) when `sshd -T`
#      (or `sshd -G` when -T cannot run) shows passwordauthentication yes, or keyboard-interactive with PAM (which asks for
#      the password too). Inert where sshd is not installed. Match blocks are not read.
#  12. Unexpected listener: event `unexpected-listener`. Warning (quiet) when a TCP or
#      UDP socket listens on a non-loopback address that is not in HOSTSEC_LISTEN_ALLOW.
#      Off until that allowlist is set; firewall-snapshot.sh prints today's line.
#  13. Container OS packages: not a card here. For each running container that
#      publishes a port (or uses the host network), the source packages of its OS
#      (dpkg or apk database, plus os-release) go to the hub as one
#      `container-packages` data report (info) per container, which the hub stores and
#      matches against OSV. Sent when a list changes and at most every
#      HOSTSEC_CTRPKG_REPORT_SECS otherwise; a resolved one once the container is gone.
#      The files are copied out with `docker cp`: nothing runs inside the container and
#      nothing is installed on the host. Inert where Docker is not installed.
#
# SAFETY:
#   - A check that CANNOT READ publishes NOTHING for its own signal (never a false
#     "0 / all-clear", and never a false "resolved" that would clear a real open
#     alert). Instead all unreadable checks fold into ONE `monitor-unreadable`
#     card, which itself resolves when every check can read again.
#   - Transition-only: state is tracked per event under $HOSTSEC_STATE_DIR, so a
#     standing condition is raised once, not re-posted every run. A still-raised
#     condition is RE-ASSERTED at most once per $HOSTSEC_RESURFACE_SECS so a
#     dismissed-but-unfixed problem resurfaces (the hub edits the open card).
#   - Per-run post cap ($HOSTSEC_MAX_POSTS); overflow is counted + logged, never
#     silently dropped, and goes on the next run.
#   - Only a 2xx counts as sent. A report that was not delivered (an error answer,
#     no network, a key the hub does not know yet) changes no state, so the next run
#     sends it again. After one post gets no answer at all, the rest of the run's posts
#     wait for the next run. A data report the hub refuses for this key (HTTP 403: a
#     `dm=` key cannot send data) is the exception: it is logged once and the same data
#     waits for its resend interval (about 20h), so it is not sent every run.
#   - Kill switch: touch $HOSTSEC_KILL_FILE (or set HOSTSEC_KILL=1) to disable.
#   - Fail-safe: the script NEVER exits non-zero and a network/tool error never
#     pages or wedges the timer.
#
# This script is READ-ONLY on the system: it simulates apt (`-s`, no lock, no
# network), stats a file, reads the journal, and for the reboot check queries dpkg,
# the Livepatch client's status (through a short transient `systemd-run` unit when
# the unit's sandbox blocks the snap) and needrestart in list mode (`-b -r l`, which
# restarts nothing), and for check 7 opens the existing apt cache read-only through
# apt-introspect.py. Checks 9-12 read the Livepatch status, run `ipv4-options-drop.sh
# --check`, print sshd's settings (`sshd -T`) and list sockets (`ss`). Check 13 streams
# a few files out of each published container (`docker cp ... -` into `tar -xO`, so
# nothing lands on disk). It installs/changes nothing.
#
# Env (all optional except the report transport's):
#   NETHERSEC_REPORT_URL / NETHERSEC_REPORT_KEY / NETHERSEC_REPORT_FORMAT  passed through
#                         to nethersec-report.sh (see its header)
#   HOSTSEC_SOURCE        box name for --source (default: `hostname -s`, lowercased)
#   HOSTSEC_GROUP         optional grouping label for --group
#   HOSTSEC_REPORT_SCRIPT path to nethersec-report.sh (default: sibling nethersec-report.sh)
#   HOSTSEC_STATE_DIR     transition-state dir (default: /var/lib/nethersec)
#   HOSTSEC_RESURFACE_SECS  re-assert a still-raised condition at most this often (default 21600 = 6h)
#   HOSTSEC_SSH_BURST     failed-login count over the window that triggers an SSH
#                         burst alert (default 2000; sized for a public box's
#                         normal background scanning so it does not cry wolf)
#   HOSTSEC_SSH_SEVERITY  severity of that SSH burst alert: critical (page) |
#                         warning (quiet, DEFAULT) | info
#   HOSTSEC_LOGERR_ENABLE set to 0 to disable just the log-error-rate check (default 1)
#   HOSTSEC_LOGERR_BURST  errors/HOUR (window-normalized) across journald+docker
#                         that trips the log-error alert (default 600; high, so a
#                         chatty box does not cry wolf; baseline then lower it)
#   HOSTSEC_LOGERR_SEVERITY  severity of that alert: critical (page) | warning
#                         (quiet, DEFAULT) | info
#   HOSTSEC_LOGERR_EXCLUDE_RE  extra grep -E alternation appended to the benign-
#                         noise exclusion (e.g. a mail server's 'NOQUEUE:.*reject')
#   HOSTSEC_SECURITY_ORIGIN_RE  extended regex; a pending `Inst` line that matches it
#                         counts as a security update even without a `-security` suite
#                         (default empty). On Raspberry Pi OS, whose archive ships
#                         Chromium, the kernel and libc6 from suite `stable`, set
#                         `Raspberry.Pi.Foundation:`
#   HOSTSEC_CVE_LOOKUP    1 (default) = resolve pending -security updates to a CVE
#                         priority via cve-severity.py and surface ONLY High/Critical;
#                         0 = disable the gate (a stuck update then cards QUIET, no page)
#   HOSTSEC_CVE_CMD       the severity-lookup command (default: python3 <dir>/cve-severity.py)
#   HOSTSEC_CVE_HARD_TIMEOUT  hard outer timeout (s) on the lookup (default 40; needs `timeout`)
#   HOSTSEC_SECUPDATE_GRACE_SECS  hold a pending security update quiet this long (timed
#                         per package, from its own first-seen) before it can surface,
#                         so a routine daily auto-upgrade clears it first
#                         (default 93600 = 26h; 0 = evaluate immediately)
#   HOSTSEC_MAX_POSTS     per-run post cap (default 8)
#   HOSTSEC_KILL_FILE     disable-if-present path (default: /etc/nethersec/disabled)
#   HOSTSEC_KILL          set to 1 to disable
#   HOSTSEC_REBOOT_FILE   reboot-required flag path (default: /var/run/reboot-required;
#                         the staged package list is the same path + `.pkgs`)
#   HOSTSEC_DPKG_QUERY    dpkg-query seam (default: dpkg-query)
#   HOSTSEC_LIVEPATCH_CMD canonical-livepatch seam (default: canonical-livepatch, or
#                         /snap/bin/canonical-livepatch when it is not on PATH)
#   HOSTSEC_SYSTEMD_RUN   runs the Livepatch call outside the unit's NoNewPrivileges when
#                         the direct call returns nothing (default: systemd-run)
#   HOSTSEC_APPLY_NEEDRESTART  needrestart seam, shared with the applier (default: needrestart)
#   HOSTSEC_REBOOT_REPORT_SECS  resend an unchanged `reboot-pending` report at most this
#                         often (default 72000 = 20h; a change is sent at once)
#   HOSTSEC_REBOOT_REPORT_ARM_SECS  hold the FIRST `reboot-pending` report this long after
#                         the detector first runs on a box (default 0: no hold). Set it to
#                         give an older hub time to be upgraded first
#   HOSTSEC_KERNEL_RELEASE  the running kernel (default: `uname -r`)
#   HOSTSEC_DPKG_INFO_DIR  dpkg's info dir, for a package's install time (default:
#                         /var/lib/dpkg/info)
#   HOSTSEC_REBOOT_UNGRADED_SECS  a kernel newer than the running one that still cannot
#                         be graded this long after its install is a card anyway
#                         (default 259200 = 3 days)
#   HOSTSEC_SCRIPT_PATH  directory check 6 walks up from (default: this script's own)
#   HOSTSEC_THIRDPARTY_ENABLE  set to 0 to disable check 7 (default 1)
#   HOSTSEC_THIRDPARTY_GRACE_SECS  how long a vendor package may wait before check 7
#                         cards it (default 604800 = 7 days)
#   HOSTSEC_THIRDPARTY_IGNORE  space-separated package names check 7 skips, e.g. a
#                         vendor package whose binary you replaced with your own build
#   HOSTSEC_DISTRO_ORIGIN_RE  extended regex of the apt origins unattended-upgrades
#                         covers; any other origin is a vendor repo for check 7
#   HOSTSEC_INTROSPECT_CMD  the upgradable-package reader (default: python3
#                         <dir>/apt-introspect.py, shared with the applier)
#   HOSTSEC_LIVE_RESTORE_ENABLE  set to 0 to disable check 8 (default 1)
#   HOSTSEC_DOCKER_CMD    docker client seam for checks 8 and 13 (default: docker)
#   HOSTSEC_OS_RELEASE    os-release file behind the Ubuntu default of checks 9 and 10
#                         (default /etc/os-release)
#   HOSTSEC_LIVEPATCH_CHECK  check 9: 1 | 0 | auto (DEFAULT: on where os-release says Ubuntu)
#   HOSTSEC_IPOPT_CHECK   check 10: 1 | 0 | auto (DEFAULT: on where os-release says Ubuntu)
#   HOSTSEC_IPOPT_CMD     check 10's command (default: bash <dir>/ipv4-options-drop.sh)
#   HOSTSEC_SSHD_CHECK    set to 0 to disable check 11 (default 1)
#   HOSTSEC_SSHD_CMD      sshd seam (default: sshd, or /usr/sbin/sshd when it is not on PATH)
#   HOSTSEC_LISTEN_ALLOW  check 12's allowlist: tokens `<proto>/<address>:<port>` with the
#                         address and port as `ss` prints them (tcp/0.0.0.0:22, udp/[::]:443),
#                         `*` for any address or any port (tcp/*:443, tcp/192.0.2.7:*),
#                         separated by spaces. Unset = check 12 off.
#   HOSTSEC_SS_CMD        ss seam for check 12 (default: ss)
#   HOSTSEC_CTRPKG_ENABLE set to 0 to disable check 13 (default 1)
#   HOSTSEC_CTRPKG_REPORT_SECS  resend an unchanged container package list at most this
#                         often (default 72000 = 20h; a change is sent at once)
#   HOSTSEC_CTRPKG_ARM_SECS  hold the FIRST package lists this long after the detector
#                         first runs on a box (default 0: no hold)
#   HOSTSEC_CTRPKG_MAX_POSTS  package lists sent per run (default 12; the rest wait for
#                         the next run). Not counted against HOSTSEC_MAX_POSTS
#   HOSTSEC_CTRPKG_MAX_PKGS  source packages listed per container (default 600)
#   HOSTSEC_CTRPKG_BUDGET_SECS  stop starting new containers after this long (default 45)
#   HOSTSEC_TAR_CMD       tar seam for check 13 (default: tar)
#
# Exit: always 0 (a oneshot that fails would trip the timer's OnFailure and read
# as an incident; failures here are logged to stderr/journald and swallowed).
set -u

log() { echo "security-report: $*" >&2; }

# --- kill switch (checked first, before any work) ----------------------------
KILL_FILE="${HOSTSEC_KILL_FILE:-/etc/nethersec/disabled}"
if [ "${HOSTSEC_KILL:-0}" = "1" ] || [ -f "$KILL_FILE" ]; then
  log "disabled (kill switch); exiting 0"
  exit 0
fi

# --- config ------------------------------------------------------------------
# The protocol's source is lowercase a-z, 0-9 and '-', so a hostname is folded to that.
SOURCE="${HOSTSEC_SOURCE:-$( (hostname -s 2>/dev/null || hostname 2>/dev/null || echo box) | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' | cut -c 1-40)}"
GROUP="${HOSTSEC_GROUP:-}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P 2>/dev/null || echo .)
REPORT="${HOSTSEC_REPORT_SCRIPT:-$SCRIPT_DIR/nethersec-report.sh}"
# apt seam: the real thing by default; the offline test harness overrides it.
APT_GET="${HOSTSEC_APT_GET:-apt-get}"
STATE_DIR="${HOSTSEC_STATE_DIR:-/var/lib/nethersec}"
RESURFACE="${HOSTSEC_RESURFACE_SECS:-21600}"
SSH_BURST="${HOSTSEC_SSH_BURST:-2000}"
# Severity for an SSH auth-burst: critical=page | warning=quiet | info.
# Default warning: on a box that takes SSH keys only, a burst is scanning noise worth
# a quiet card, not a 3am page. Set HOSTSEC_SSH_SEVERITY=critical per box only where
# password auth is enabled.
SSH_SEVERITY="${HOSTSEC_SSH_SEVERITY:-warning}"
case "$SSH_SEVERITY" in critical|warning|info) ;; *) SSH_SEVERITY="warning" ;; esac
# CVE-severity gate (REPLACES the old crown-jewel HOSTSEC_PAGE_PKGS list). A pending
# security update is surfaced ONLY when it fixes a HIGH or CRITICAL Ubuntu CVE; low/
# medium updates auto-apply silently. cve-severity.py resolves the pending set to a
# CVE priority + link (cached under STATE_DIR, fail-safe: any failure => 'unknown'/
# 'error', never a fabricated High/Critical). Disable per box (no egress to
# ubuntu.com) with HOSTSEC_CVE_LOOKUP=0; a stuck update then cards QUIET (no page).
CVE_LOOKUP="${HOSTSEC_CVE_LOOKUP:-1}"
CVE_CMD="${HOSTSEC_CVE_CMD:-python3 -I $SCRIPT_DIR/cve-severity.py}"
# Hard outer timeout on the lookup (belt for the helper's own per-request + run
# budget); skipped where `timeout` is unavailable.
if command -v timeout >/dev/null 2>&1; then CVE_WRAP="timeout ${HOSTSEC_CVE_HARD_TIMEOUT:-40}"; else CVE_WRAP=""; fi
# Grace window for a pending security update: hold it QUIET until THAT package has been
# pending longer than this (each package runs its own clock from when it was first seen,
# so a late joiner never inherits an older batch's age), so a routine same-day
# auto-upgrade (unattended-upgrades applies the
# -security pocket at the daily apt window) clears it BEFORE it can ever surface.
# Default 93600s (26h) = one full daily auto-upgrade window + margin, so only a STUCK
# update (auto-upgrade failed/held it back) is evaluated; and then it pages ONLY if
# it is High/Critical. Set 0 to evaluate immediately.
SECUPDATE_GRACE_SECS="${HOSTSEC_SECUPDATE_GRACE_SECS:-93600}"
case "$SECUPDATE_GRACE_SECS" in ''|*[!0-9]*) SECUPDATE_GRACE_SECS=93600 ;; esac
MAX_POSTS="${HOSTSEC_MAX_POSTS:-8}"
# Extra origins whose pending updates count as security updates (see check 1).
SECURITY_ORIGIN_RE="${HOSTSEC_SECURITY_ORIGIN_RE:-}"
# Check 7 (vendor apt packages nothing installs). The distro origins are the ones
# unattended-upgrades covers; anything else is a vendor repo.
THIRDPARTY_ENABLE="${HOSTSEC_THIRDPARTY_ENABLE:-1}"
THIRDPARTY_GRACE_SECS="${HOSTSEC_THIRDPARTY_GRACE_SECS:-604800}"
case "$THIRDPARTY_GRACE_SECS" in ''|*[!0-9]*) THIRDPARTY_GRACE_SECS=604800 ;; esac
THIRDPARTY_IGNORE="${HOSTSEC_THIRDPARTY_IGNORE:-}"
DISTRO_ORIGIN_RE="${HOSTSEC_DISTRO_ORIGIN_RE:-^(Ubuntu|UbuntuESM|UbuntuESMApps|UbuntuFIPS|Debian|Raspbian|Raspberry Pi Foundation)$}"
INTROSPECT_CMD="${HOSTSEC_INTROSPECT_CMD:-python3 -I $SCRIPT_DIR/apt-introspect.py}"
# Check 8 (Docker live-restore).
LIVE_RESTORE_ENABLE="${HOSTSEC_LIVE_RESTORE_ENABLE:-1}"
DOCKER_CMD="${HOSTSEC_DOCKER_CMD:-docker}"
# Checks 9-12 (box drift). Livepatch and the IP-options drop are for Ubuntu servers,
# so `auto` turns those two checks on where os-release says Ubuntu, and leaves them off
# elsewhere (Debian, Raspberry Pi OS).
OS_RELEASE="${HOSTSEC_OS_RELEASE:-/etc/os-release}"
OS_ID=$(sed -n 's/^ID=//p' "$OS_RELEASE" 2>/dev/null | tr -d '"' | head -n 1)
on_ubuntu() { case "$1" in 0|1) echo "$1" ;; *) if [ "$OS_ID" = ubuntu ]; then echo 1; else echo 0; fi ;; esac; }
LIVEPATCH_CHECK=$(on_ubuntu "${HOSTSEC_LIVEPATCH_CHECK:-auto}")
IPOPT_CHECK=$(on_ubuntu "${HOSTSEC_IPOPT_CHECK:-auto}")
IPOPT_CMD="${HOSTSEC_IPOPT_CMD:-bash $SCRIPT_DIR/ipv4-options-drop.sh}"
SSHD_CHECK="${HOSTSEC_SSHD_CHECK:-1}"
if [ -n "${HOSTSEC_SSHD_CMD:-}" ]; then
  SSHD_CMD="$HOSTSEC_SSHD_CMD"
elif command -v sshd >/dev/null 2>&1; then
  SSHD_CMD="sshd"
else
  SSHD_CMD="/usr/sbin/sshd"
fi
LISTEN_ALLOW="${HOSTSEC_LISTEN_ALLOW:-}"
SS_CMD="${HOSTSEC_SS_CMD:-ss}"
# Check 13 (container OS packages).
CTRPKG_ENABLE="${HOSTSEC_CTRPKG_ENABLE:-1}"
CTRPKG_REPORT_EVERY="${HOSTSEC_CTRPKG_REPORT_SECS:-72000}"
case "$CTRPKG_REPORT_EVERY" in ''|*[!0-9]*) CTRPKG_REPORT_EVERY=72000 ;; esac
CTRPKG_ARM="${HOSTSEC_CTRPKG_ARM_SECS:-0}"
case "$CTRPKG_ARM" in ''|*[!0-9]*) CTRPKG_ARM=0 ;; esac
CTRPKG_MAX_POSTS="${HOSTSEC_CTRPKG_MAX_POSTS:-12}"
case "$CTRPKG_MAX_POSTS" in ''|*[!0-9]*) CTRPKG_MAX_POSTS=12 ;; esac
CTRPKG_MAX_PKGS="${HOSTSEC_CTRPKG_MAX_PKGS:-600}"
case "$CTRPKG_MAX_PKGS" in ''|*[!0-9]*) CTRPKG_MAX_PKGS=600 ;; esac
CTRPKG_BUDGET="${HOSTSEC_CTRPKG_BUDGET_SECS:-45}"
case "$CTRPKG_BUDGET" in ''|*[!0-9]*) CTRPKG_BUDGET=45 ;; esac
TAR_CMD="${HOSTSEC_TAR_CMD:-tar}"
# Log error-rate check (see check_log_errors). Default quiet + HIGH threshold:
# app/container error logs are noisier than SSH auth (one crash-looping container
# or a chatty library can emit thousands of ERROR lines in a window), so a low or
# `critical` default would page all day. Baseline each box, then ratchet the
# threshold down / severity up.
LOGERR_ENABLE="${HOSTSEC_LOGERR_ENABLE:-1}"
LOGERR_BURST="${HOSTSEC_LOGERR_BURST:-600}"
LOGERR_SEVERITY="${HOSTSEC_LOGERR_SEVERITY:-warning}"
case "$LOGERR_SEVERITY" in critical|warning|info) ;; *) LOGERR_SEVERITY="warning" ;; esac
# Reboot check (check 2). The seams default to the real tools; the harness mocks them.
REBOOT_FLAG="${HOSTSEC_REBOOT_FILE:-/var/run/reboot-required}"
DPKG_QUERY="${HOSTSEC_DPKG_QUERY:-dpkg-query}"
if [ -n "${HOSTSEC_LIVEPATCH_CMD:-}" ]; then
  LIVEPATCH_CMD="$HOSTSEC_LIVEPATCH_CMD"
elif command -v canonical-livepatch >/dev/null 2>&1; then
  LIVEPATCH_CMD="canonical-livepatch"
else
  LIVEPATCH_CMD="/snap/bin/canonical-livepatch"   # a snap; not always on a unit's PATH
fi
# A snap cannot start under the unit's NoNewPrivileges (snap is refused the AppArmor
# profile change), so a direct Livepatch call from the unit returns nothing. Then the
# same read-only command runs once through this, in a short transient unit without that
# setting (still a read-only home and its own /tmp). A missing command skips it.
SYSTEMD_RUN="${HOSTSEC_SYSTEMD_RUN:-systemd-run}"
NEEDRESTART_BIN="${HOSTSEC_APPLY_NEEDRESTART:-needrestart}"
REBOOT_REPORT_EVERY="${HOSTSEC_REBOOT_REPORT_SECS:-72000}"
case "$REBOOT_REPORT_EVERY" in ''|*[!0-9]*) REBOOT_REPORT_EVERY=72000 ;; esac
REBOOT_REPORT_ARM="${HOSTSEC_REBOOT_REPORT_ARM_SECS:-0}"
case "$REBOOT_REPORT_ARM" in ''|*[!0-9]*) REBOOT_REPORT_ARM=0 ;; esac
# The running kernel (`uname -r`) and dpkg's info dir (a package's install time is the
# mtime of its .list file). A kernel newer than the running one that still cannot be
# graded after this long is a card anyway (3 days).
KERNEL_RELEASE="${HOSTSEC_KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"
DPKG_INFO_DIR="${HOSTSEC_DPKG_INFO_DIR:-/var/lib/dpkg/info}"
REBOOT_UNGRADED_SECS="${HOSTSEC_REBOOT_UNGRADED_SECS:-259200}"
case "$REBOOT_UNGRADED_SECS" in ''|*[!0-9]*) REBOOT_UNGRADED_SECS=259200 ;; esac
# Short outer limits on the two local tools (the unit allows 120s for the whole run).
if [ -n "$CVE_WRAP" ]; then LP_WRAP="timeout 15"; NR_WRAP="timeout 30"; DL_WRAP="timeout 20"; else LP_WRAP=""; NR_WRAP=""; DL_WRAP=""; fi

# The transport needs a URL, and a key unless the format works without one (Discord,
# ntfy, json). Without them nothing can be posted, so fail SAFE (log + exit 0) rather
# than record a state change nobody was told about.
report_ready() {
  [ -n "${NETHERSEC_REPORT_URL:-}" ] || return 1
  [ -n "${NETHERSEC_REPORT_KEY:-}" ] && return 0
  case "${NETHERSEC_REPORT_FORMAT:-}" in discord|ntfy|json) return 0 ;; '') ;; *) return 1 ;; esac
  case "$NETHERSEC_REPORT_URL" in
    https://discord.com/api/webhooks/*|https://*.discord.com/api/webhooks/*|https://discordapp.com/api/webhooks/*|https://*.discordapp.com/api/webhooks/*) return 0 ;;
  esac
  return 1
}
if ! report_ready; then
  log "NETHERSEC_REPORT_URL (or the hub format's NETHERSEC_REPORT_KEY) unset; nothing to post to. Exiting 0."
  exit 0
fi
if [ ! -x "$REPORT" ] && [ ! -f "$REPORT" ]; then
  log "report transport not found at $REPORT; exiting 0"
  exit 0
fi

if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
  log "cannot create state dir $STATE_DIR; exiting 0"
  exit 0
fi

NOW="${HOSTSEC_NOW:-$(date +%s 2>/dev/null || echo 0)}"
case "$NOW" in ''|*[!0-9]*) NOW=0 ;; esac
POSTS=0
OVERFLOW=0
# Set once a post got no answer at all (nethersec-report.sh exit 3: no network, a
# timeout). The rest of this run's posts then wait for the next run instead of each
# waiting out its own timeout, which could run the unit past its time limit.
HUB_DOWN=0
DEFERRED=0

# --- post helper: respects the per-run cap; never aborts on transport error ---
# EMIT_OK says whether THIS post was delivered (1) or not (0: over the cap, the
# transport failed, or the hub did not answer earlier in this run). Every caller
# records a report as sent only when EMIT_OK is 1, so anything else goes again on the
# next run.
EMIT_OK=0
# EMIT_REFUSED is 1 when the hub refused THIS data event for this box's key (HTTP 403,
# nethersec-report.sh exit 4). Its caller logs that and waits (see data_refused below);
# any other report that is refused goes again on the next run, as before.
EMIT_REFUSED=0
emit() {
  EMIT_OK=0; EMIT_REFUSED=0
  if [ "$POSTS" -ge "$MAX_POSTS" ]; then
    OVERFLOW=$((OVERFLOW + 1))
    return 0
  fi
  if [ "$HUB_DOWN" = 1 ]; then
    DEFERRED=$((DEFERRED + 1))
    return 0
  fi
  POSTS=$((POSTS + 1))
  if [ -n "$GROUP" ]; then
    sh "$REPORT" --kind security --source "$SOURCE" --group "$GROUP" "$@" >/dev/null 2>&1
  else
    sh "$REPORT" --kind security --source "$SOURCE" "$@" >/dev/null 2>&1
  fi
  em_rc=$?
  # Every emit call starts with `--event <name>`, so $2 is the event.
  em_data=0
  case "${2:-}" in reboot-pending|container-packages) em_data=1 ;; esac
  if [ "$em_rc" -eq 0 ]; then
    EMIT_OK=1
  elif [ "$em_rc" -eq 4 ] && [ "$em_data" = 1 ]; then
    EMIT_REFUSED=1   # its caller logs it once and waits (data_refused)
  else
    [ "$em_rc" -eq 3 ] && HUB_DOWN=1
    log "post failed (source=$SOURCE): $*"
  fi
}

# --- a data event the hub refused (HTTP 403) ----------------------------------
# The hub answers 403 to the data events (reboot-pending, container-packages) from a key
# that may not send them (a `dm=` key). The same data gets the same answer, so it is not
# sent again every run: the refusal is recorded as "<epoch> <what was refused>", and the
# same data waits for its usual resend interval. Changed data goes at once.
# data_refused_recently FILE WHAT EVERY -> 0 when FILE says WHAT was refused less than
# EVERY seconds ago.
data_refused_recently() {
  [ -f "$1" ] || return 1
  dr_line=""; IFS= read -r dr_line < "$1" 2>/dev/null || :
  dr_at="${dr_line%% *}"; dr_what="${dr_line#* }"
  case "$dr_at" in ''|*[!0-9]*) return 1 ;; esac
  [ "$dr_what" = "$2" ] && [ "$dr_at" -le "$NOW" ] && [ $((NOW - dr_at)) -lt "$3" ]
}
# data_refused FILE WHAT LABEL EVERY: record the refusal and say so, once.
data_refused() {
  put_state "$1" "$NOW $2"
  log "the hub refused $3 for this key (HTTP 403; a dm= key cannot send data); it goes again when it changes, or in ${4}s"
}

# --- state write: temp + rename, never fatal ---------------------------------
# Replaces a clock file whole, so a crash or a full disk mid-write can never leave a
# TRUNCATED clock behind (an empty/garbled clock would silently restart a grace
# window). A failed write is logged and the run carries on (exit 0 always).
put_state() {
  # $1=file  $2=content (written with a trailing newline)
  ps_tmp="$1.tmp.$$"
  if printf '%s\n' "$2" > "$ps_tmp" 2>/dev/null && mv -f "$ps_tmp" "$1" 2>/dev/null; then
    return 0
  fi
  rm -f "$ps_tmp" 2>/dev/null
  log "state write failed: $1"
  return 0
}

# --- transition engine: raise once, resolve once, throttled re-surface --------
# state file $STATE_DIR/ev.<event> holds "<severity> <assertEpoch> [<key>]" while raised;
# absent = ok. An UNREADABLE check must NOT call this (leave its state untouched).
# The state file says what the hub was last TOLD, so it changes only after a 2xx. A
# raise that failed or was over the cap writes nothing and goes again on the next run
# (if the condition cleared by then, nothing was ever posted and nothing is resolved).
# A resolve that failed keeps the file, so it goes again on the next run too.
transition() {
  # $1=event  $2=curstate(ok|raised)  $3=severity  $4=title  $5=detail  [$6=key]
  # The optional key names WHAT is raised (check 12: its set of listeners), so a change
  # to it is re-asserted at once and the card names the new set.
  te_ev="$1"; te_cur="$2"; te_sev="$3"; te_title="$4"; te_detail="$5"; te_key="${6:-}"
  te_f="$STATE_DIR/ev.$te_ev"
  if [ "$te_cur" = "raised" ]; then
    if [ -f "$te_f" ]; then
      te_ssev=""; te_sasrt=0; te_skey=""
      read -r te_ssev te_sasrt te_skey < "$te_f" 2>/dev/null || { te_ssev=""; te_sasrt=0; te_skey=""; }
      case "$te_sasrt" in ''|*[!0-9]*) te_sasrt=0 ;; esac
      # Re-assert on a severity change (e.g. warning→critical), a key change, or once
      # the re-surface interval has elapsed; otherwise stay quiet (already raised).
      # A failed re-assert keeps the old line, so its severity, key or age still
      # differs on the next run and it goes again.
      if [ "$te_ssev" = "$te_sev" ] && [ "$te_skey" = "$te_key" ] && [ $((NOW - te_sasrt)) -lt "$RESURFACE" ]; then
        return 0
      fi
    fi
    emit --event "$te_ev" --state triggered --severity "$te_sev" --title "$te_title" --detail "$te_detail"
    [ "$EMIT_OK" = "1" ] || return 0
    printf '%s %s%s\n' "$te_sev" "$NOW" "${te_key:+ $te_key}" > "$te_f" 2>/dev/null || log "state write failed: $te_f"
  else
    # ok: resolve only if we currently hold it open.
    if [ -f "$te_f" ]; then
      emit --event "$te_ev" --state resolved --title "$te_title"
      [ "$EMIT_OK" = "1" ] || return 0
      rm -f "$te_f" 2>/dev/null || log "state clear failed: $te_f"
    fi
  fi
}

# Checks set these globals, then the caller acts on them.
R_STATE="ok"    # ok | raised | unreadable
R_SEV="warning" # critical | warning | info  (when raised)
R_DETAIL=""
R_DONE=0        # check 1 only: 1 => also emit a one-shot "done" note (episode cleared)
R_DONE_DETAIL=""
R_KEY=""        # check 12 only: names the raised set (transition's optional key)
UNREADABLE=""   # accumulates names of checks that could not read

# --- check 1: pending security updates ---------------------------------------
# SILENT while every pending update is within its own grace; a QUIET one-shot "done"
# note on clear (High/Critical only); a critical PAGE only for a High/Critical CVE
# whose package is itself STUCK past grace, and ONE quiet non-paging card for stuck
# packages that are only low/medium (a stopped-unattended-upgrades liveness signal). Severity comes from
# cve-severity.py, which fails safe to 'unknown'/'error' and NEVER fabricates a
# High/Critical (so a lookup outage can never manufacture a page). Nothing below
# keys off a package NAME; only the
# resolved CVE priority (and, for the stuck-page, whether that package is still pending).
check_security_updates() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""; R_DONE=0; R_DONE_DETAIL=""
  cs_since_f="$STATE_DIR/pending-since.security-updates"
  # Per-package state (see "per-package grace" below), one TAB-separated row per package:
  #   name  first_seen  version  gone_since  prio  cve  link
  cs_first_f="$STATE_DIR/first-seen.security-updates.tsv"
  # Every clock here is measured against NOW. A run whose `date +%s` failed (the 0
  # fallback) would clamp every stored clock to 0, and the next run would throw them
  # all away: a stuck High silent for another full grace. So no clock = UNREADABLE,
  # and neither state file is touched.
  [ "$NOW" -gt 0 ] || { R_STATE="unreadable"; return; }
  if ! command -v "$APT_GET" >/dev/null 2>&1; then
    R_STATE="unreadable"; return
  fi
  # Simulated dist-upgrade: no lock, no network, read-only. dist-upgrade (not plain
  # upgrade) so a held-back kernel security update is still seen. Security updates
  # carry a `-security` (or `-*-security`, incl. ESM) pocket on the ^Inst line. Parse
  # each pending one as `name<TAB>candidate_version`. name=$2 (strip a `:arch`
  # suffix; a NAME never has a ':', but the VERSION's epoch does, so strip the name
  # ONLY). The candidate version is the token that OPENS with '(': on an UPGRADE line
  # `Inst n [old] (new …)` that is $4, but a NEW-INSTALL line `Inst n (new …)` (a
  # versioned kernel image, a soname bump) has it at $3; so SCAN for the '('-prefixed
  # field, never assume $4. The version is what cve-severity.py exact-matches to a USN.
  # A box whose security fixes ship from an origin without a `-security` suite
  # (Raspberry Pi OS's archive: `Raspberry Pi Foundation:stable`) names it in
  # HOSTSEC_SECURITY_ORIGIN_RE, and a line matching it counts too.
  cs_sim=$(LC_ALL=C "$APT_GET" -s dist-upgrade 2>/dev/null)
  if [ $? -ne 0 ] || [ -z "$cs_sim" ]; then
    # apt errored (locked cache mid-update, broken state, …); do NOT claim 0.
    # Leave BOTH state files untouched (UNREADABLE is not "caught up").
    R_STATE="unreadable"; return
  fi
  cs_pairs=$(printf '%s\n' "$cs_sim" | awk -v xre="$SECURITY_ORIGIN_RE" '/^Inst / && (/-security/ || (xre != "" && $0 ~ xre)) {
      name=$2; sub(/:.*/,"",name);
      ver=""; for(i=3;i<=NF;i++) if(substr($i,1,1)=="("){ver=substr($i,2);break}
      if (name!="" && ver!="") print name"\t"ver }' | sort -u)
  cs_names=$(printf '%s\n' "$cs_pairs" | awk -F'\t' 'NF{print $1}' | sort -u)
  cs_count=$(printf '%s\n' "$cs_names" | awk 'NF' | wc -l | tr -d ' ')

  if [ "${cs_count:-0}" -eq 0 ]; then
    # Fully caught up. If we were tracking a pending episode, emit a one-shot QUIET
    # "done" note; but ONLY when a High/Critical CVE was seen in it (low/medium
    # generate NO notification). Then clear both state files.
    if [ -f "$cs_since_f" ]; then
      cs_dprio=""; cs_dcve=""; cs_dlink=""
      read -r _ds _dc cs_dprio _dpkg cs_dcve cs_dlink < "$cs_since_f" 2>/dev/null || :
      case "$cs_dprio" in
        high|critical)
          R_DONE=1
          R_DONE_DETAIL="security update(s) auto-applied on ${SOURCE}. included a ${cs_dprio} CVE${cs_dcve:+ ($cs_dcve)}${cs_dlink:+ $cs_dlink}" ;;
      esac
      rm -f "$cs_since_f" 2>/dev/null
    fi
    rm -f "$cs_first_f" 2>/dev/null
    R_STATE="ok"; return
  fi

  # Something is pending. Read the EPISODE memory. Space-separated; the two OPTIONAL
  # fields (cve, link) come LAST; after the load-bearing pkg name; so that an empty
  # cve/link (a graded High whose CVE id was rejected) collapses harmlessly at the end of
  # a default-IFS read instead of shifting pkg out of its slot. Fields:
  #   <first_seen_epoch> <count> <max_prio_seen> <top_pkg_seen> <top_cve_seen> <top_link_seen>
  # first_seen_epoch is the OLDEST first-seen among the CURRENTLY pending packages (same
  # slot + meaning for a single-batch episode, so older readers/tools stay valid); the
  # per-package clocks that actually drive the grace live in $cs_first_f.
  # max_prio_seen carries the HIGHEST CVE priority observed ACROSS the whole episode; it
  # feeds the done-gate. top_pkg/cve/link name that High/Critical. The stuck-page does NOT
  # use them any more: every package keeps its OWN grade in $cs_first_f (one episode-wide
  # slot let a fresher Critical overwrite an older stuck High's memory, and resurrected a
  # High for a package that had since been applied). They are read once more only to
  # seed that package's grade when migrating from the old single-line file. Only
  # high/critical are ever stored. Back-compatible with an older single-token file.
  cs_since=0; cs_wprio=""; cs_wcve=""; cs_wlink=""; cs_wpkg=""
  if [ -f "$cs_since_f" ]; then
    read -r cs_since _oc cs_wprio cs_wpkg cs_wcve cs_wlink < "$cs_since_f" 2>/dev/null || cs_since=0
    case "$cs_since" in ''|*[!0-9]*) cs_since=0 ;; esac
  fi

  # --- CVE-severity gate: grade the WHOLE pending set (not just the stuck part). ---
  # The episode max feeds the done-gate, and each package's grade is stored in its own
  # row below, so a later run still knows it if that run's lookup blips.
  cs_max=""; cs_cve=""; cs_link=""; cs_pkg=""; cs_sev=""
  if [ "$CVE_LOOKUP" = "1" ]; then
    cs_sev=$(printf '%s\n' "$cs_pairs" | HOSTSEC_STATE_DIR="$STATE_DIR" $CVE_WRAP $CVE_CMD 2>/dev/null)
    if printf '%s\n' "$cs_sev" | awk -F'\t' '$2=="critical"{f=1} END{exit !f}'; then
      cs_max="critical"; cs_l=$(printf '%s\n' "$cs_sev" | awk -F'\t' '$2=="critical"{print; exit}')
    elif printf '%s\n' "$cs_sev" | awk -F'\t' '$2=="high"{f=1} END{exit !f}'; then
      cs_max="high"; cs_l=$(printf '%s\n' "$cs_sev" | awk -F'\t' '$2=="high"{print; exit}')
    else
      cs_l=""
    fi
    [ -n "$cs_l" ] && { cs_cve=$(printf '%s' "$cs_l" | cut -f3); cs_link=$(printf '%s' "$cs_l" | cut -f4); cs_pkg=$(printf '%s' "$cs_l" | cut -f1); }
  fi
  # Remember the highest priority seen across the episode (critical > high > stored).
  # Read the stored top_pkg BEFORE this can overwrite it: the migration seed below needs
  # the one the old file named.
  cs_mpkg="$cs_wpkg"; cs_mprio="$cs_wprio"; cs_mcve="$cs_wcve"; cs_mlink="$cs_wlink"
  cs_rank=0; case "$cs_max" in critical) cs_rank=2 ;; high) cs_rank=1 ;; esac
  cs_wrank=0; case "$cs_wprio" in critical) cs_wrank=2 ;; high) cs_wrank=1 ;; esac
  if [ "$cs_rank" -gt "$cs_wrank" ]; then cs_wprio="$cs_max"; cs_wcve="$cs_cve"; cs_wlink="$cs_link"; cs_wpkg="$cs_pkg"; fi

  # --- per-package grace (why not one episode clock) ---
  # The grace exists to give unattended-upgrades one daily window to apply a fix before
  # we call it STUCK. That window is per PACKAGE: a fix that reaches -security today has
  # had no window yet, no matter how long some OTHER package kept the pending set
  # non-empty. An episode-wide clock (reset only when the set goes EMPTY) let a new
  # package inherit an older batch's age, so a fix pending 6h could page as "STUCK 38h"
  # when it would have auto-applied at the next daily run. So each package keeps its
  # OWN row: first-seen, candidate version, and
  # the highest High/Critical grade seen for it while pending. Rebuilt every run:
  #   - a name pending last run keeps its first-seen and grade, even across a new
  #     candidate version (it was never applied, so an older High fix is still missing);
  #   - a name that leaves the set is kept for $cs_keep as a TOMBSTONE (gone_since set).
  #     If it comes back at the SAME version inside that window it was never applied
  #     (a resolver keep-back or a mirror blip hid it for a run or two), so it resumes
  #     its first-seen and grade: the page is not pushed back a whole grace. A different
  #     version, or a return after the window, is a fresh package (the old one was
  #     applied), with a fresh clock and no inherited grade;
  #   - a new name starts at NOW;
  #   - first-seen / gone_since stamped in the FUTURE (a skewed RTC) are clamped to NOW,
  #     so a skewed stamp can delay a page by at most one grace.
  # The table is trusted only when it agrees with the episode line (field 1 = the oldest
  # first-seen of the table's pending rows: both are written together, every run). If it
  # does not; no valid row at all (first run after this change, a lost write), or a stale
  # table left behind by a rollback to the old single-clock code, which never removed it -
  # every pending name is seeded from the episode start instead (MIGRATION), and the
  # package the old line named gets its stored grade. Conservative on purpose: an
  # in-progress stuck page survives (it may page early for one episode, never late). An
  # unreadable episode line (0) cannot contradict the table, so the table is used.
  # Malformed rows (no tab, non-numeric or zero epoch) are ignored, never fatal. Epochs
  # are carried as the original STRINGS and only compared numerically, so no awk
  # (mawk) ever reformats a large epoch into 1.78e+09 on the way out. No field is ever
  # written empty ('-' placeholder).
  cs_keep=21600   # tombstone window: 6h = 12 detector runs at the 30-min timer
  cs_tab=$( { printf '%s\n' "$cs_pairs" | awk -F'\t' 'NF >= 2 && $1 != "" { print "P\t" $1 "\t" $2 }'
              printf '%s\n' "$cs_sev" | awk -F'\t' 'NF >= 2 && $1 != "" { print "G\t" $0 }'; } |
    awk -F'\t' -v now="$NOW" -v legacy="$cs_since" -v f="$cs_first_f" -v keep="$cs_keep" \
        -v wpkg="$cs_mpkg" -v wprio="$cs_mprio" -v wcve="$cs_mcve" -v wlink="$cs_mlink" '
    function rank(p) { return (p == "critical") ? 2 : ((p == "high") ? 1 : 0) }
    function dash(s) { return (s == "") ? "-" : s }
    function undash(s) { return (s == "-") ? "" : s }
    BEGIN { nv = 0; tmin = ""
      while ((getline ln < f) > 0) {
        m = split(ln, c, "\t"); n = c[1]; t = c[2]
        if (n == "" || m < 2 || t !~ /^[0-9]+$/ || t + 0 <= 0) continue
        g = 0; if (m >= 4 && c[4] ~ /^[0-9]+$/) g = c[4]
        # the agreement check uses the stamps as WRITTEN (before the clamp below)
        if (g + 0 == 0 && (tmin == "" || t + 0 < tmin + 0)) tmin = t
        if (t + 0 > now + 0) t = now
        if (g + 0 > now + 0) g = now
        of[n] = t; og[n] = g; ov[n] = (m >= 3) ? c[3] : "-"
        op[n] = ""; oc[n] = ""; ol[n] = ""
        if (m >= 5 && rank(c[5]) > 0) { op[n] = c[5]; oc[n] = undash(c[6]); ol[n] = undash(c[7]) }
        nv++
      }
      close(f)
      trust = (nv > 0 && (legacy + 0 <= 0 || (tmin != "" && tmin + 0 == legacy + 0)))
    }
    $1 == "P" { if (!($2 in cv)) { cv[$2] = $3; ord[++np] = $2 } next }
    $1 == "G" { if (rank($3) > rank(fp[$2])) { fp[$2] = $3; fc[$2] = $4; fl[$2] = $5 } next }
    END {
      for (i = 1; i <= np; i++) {
        n = ord[i]; v = cv[n]; t = ""; p = ""; cc = ""; ll = ""
        if (trust && (n in of)) {
          if (og[n] + 0 == 0 || (ov[n] == v && now - og[n] < keep + 0)) {
            t = of[n]; p = op[n]; cc = oc[n]; ll = ol[n]
          }
        } else if (!trust && legacy + 0 > 0) {
          t = legacy
          if (n == wpkg && rank(wprio) > 0) { p = wprio; cc = wcve; ll = wlink }
        }
        if (t == "" || t + 0 > now + 0) t = now
        if (rank(fp[n]) > 0 && rank(fp[n]) >= rank(p)) { p = fp[n]; cc = fc[n]; ll = fl[n] }
        print n "\t" t "\t" v "\t0\t" dash(p) "\t" dash(cc) "\t" dash(ll)
      }
      if (trust) for (n in of) if (!(n in cv)) {
        g = (og[n] + 0 == 0) ? now : og[n]
        if (now - g < keep + 0) print n "\t" of[n] "\t" dash(ov[n]) "\t" g "\t" dash(op[n]) "\t" dash(oc[n]) "\t" dash(ol[n])
      }
    }')
  # Episode start (field 1) = the oldest CURRENT first-seen; the STUCK set = the pending
  # names whose OWN clock is past grace. (Rows with gone_since != 0 are tombstones.)
  cs_since=$(printf '%s\n' "$cs_tab" | awk -F'\t' 'NF >= 4 && $4 == 0 && (m == "" || $2 + 0 < m + 0) { m = $2 } END { print m }')
  case "$cs_since" in ''|*[!0-9]*) cs_since="$NOW" ;; esac
  cs_stuck=$(printf '%s\n' "$cs_tab" | awk -F'\t' -v now="$NOW" -v g="$SECUPDATE_GRACE_SECS" 'NF >= 4 && $4 == 0 && now - $2 >= g { print $1 }')
  cs_nstuck=$(printf '%s\n' "$cs_stuck" | awk 'NF' | wc -l | tr -d ' ')
  # " a b c "; space-delimited so a whole-name membership test is one index()/case
  # (package names never contain whitespace).
  cs_stuck_sp=" $(printf '%s\n' "$cs_stuck" | tr '\n' ' ')"
  put_state "$cs_first_f" "$cs_tab"
  put_state "$cs_since_f" "$(printf '%s %s %s %s %s %s' "$cs_since" "$cs_count" "$cs_wprio" "$cs_wpkg" "$cs_wcve" "$cs_wlink")"

  if [ "${cs_nstuck:-0}" -eq 0 ]; then
    R_STATE="ok"; return   # every pending package is within its OWN grace → quiet
  fi

  # Past grace = unattended-upgrades did NOT apply it (STUCK). Surface per severity, and
  # describe ONLY the stuck packages (a within-grace one is merely counted, and a
  # within-grace High/Critical is named as such so the quiet card never reads "all clear").
  cs_hrs=$(( (NOW - cs_since) / 3600 ))   # oldest pending = oldest stuck
  cs_sample=$(printf '%s\n' "$cs_stuck" | head -12 | tr '\n' ' ')
  cs_more=$((cs_nstuck - 12)); [ "$cs_more" -lt 0 ] && cs_more=0
  cs_moretxt=""; [ "$cs_more" -gt 0 ] && cs_moretxt="(+$cs_more more)"
  cs_within=$((cs_count - cs_nstuck))
  cs_withinhc=$(printf '%s\n' "$cs_tab" | awk -F'\t' -v now="$NOW" -v g="$SECUPDATE_GRACE_SECS" '
    NF >= 7 && $4 == 0 && now - $2 < g && ($5 == "high" || $5 == "critical") { c++ } END { print c + 0 }')
  case "$cs_withinhc" in ''|*[!0-9]*) cs_withinhc=0 ;; esac
  cs_withintxt=""
  if [ "$cs_within" -gt 0 ]; then
    if [ "$cs_withinhc" -gt 0 ]; then
      cs_withintxt=" (+$cs_within newer incl. $cs_withinhc High/Critical, still within the auto-apply window)"
    else
      cs_withintxt=" (+$cs_within newer, still within the auto-apply window)"
    fi
  fi
  # Is a High/Critical CVE STILL pending AND its package itself past grace? Read from the
  # per-package rows: each carries the highest grade seen for it while pending (this
  # run's fresh lookup merged with what earlier runs stored). So a lookup blip this run
  # still pages for a package graded High before, whichever other package is graded or
  # joins meanwhile; an applied package's grade left with it (a new version starts
  # ungraded); and a fresh one that has not had its own auto-apply window never pages.
  # Critical beats High; among equals the longest-pending wins.
  cs_page_prio=""; cs_page_cve=""; cs_page_link=""; cs_page_pkg=""; cs_pfirst=""
  cs_page=$(printf '%s\n' "$cs_tab" | awk -F'\t' -v now="$NOW" -v g="$SECUPDATE_GRACE_SECS" '
    NF >= 7 && $4 == 0 && now - $2 >= g && ($5 == "critical" || $5 == "high") {
      r = ($5 == "critical") ? 2 : 1
      if (r > br || (r == br && $2 + 0 < bt + 0)) { br = r; bt = $2; b = $0 } }
    END { if (b != "") print b }')
  if [ -n "$cs_page" ]; then
    cs_page_pkg=$(printf '%s' "$cs_page" | cut -f1); cs_pfirst=$(printf '%s' "$cs_page" | cut -f2)
    cs_page_prio=$(printf '%s' "$cs_page" | cut -f5)
    cs_page_cve=$(printf '%s' "$cs_page" | cut -f6); cs_page_link=$(printf '%s' "$cs_page" | cut -f7)
    [ "$cs_page_cve" = "-" ] && cs_page_cve=""
    [ "$cs_page_link" = "-" ] && cs_page_link=""
  fi
  if [ -n "$cs_page_prio" ]; then
    # A High/Critical CVE is stuck past its own auto-apply window → PAGE (page). Name the
    # package and ITS age, so the page never borrows an older batch's clock.
    case "$cs_pfirst" in ''|*[!0-9]*) cs_pfirst="$cs_since" ;; esac
    cs_phrs=$(( (NOW - cs_pfirst) / 3600 ))
    R_STATE="raised"; R_SEV="critical"
    R_DETAIL="$cs_nstuck pending security update(s) STUCK ${cs_hrs}h; auto-upgrade did not apply them. highest: ${cs_page_prio} CVE${cs_page_cve:+ ($cs_page_cve)}${cs_page_link:+ $cs_page_link} in ${cs_page_pkg} (pending ${cs_phrs}h). pkgs: ${cs_sample}${cs_moretxt}${cs_withintxt}"
    return
  fi
  if [ "$CVE_LOOKUP" != "1" ]; then
    # Gate disabled → severity is unknowable here; surface a QUIET card (no page) so
    # a stuck update is never silently ignored on a box that opted out of the lookup.
    R_STATE="raised"; R_SEV="warning"
    R_DETAIL="$cs_nstuck pending security update(s) STUCK ${cs_hrs}h; auto-upgrade did not apply them (CVE gate disabled). pkgs: ${cs_sample}${cs_moretxt}${cs_withintxt}"
    return
  fi
  # Could every STUCK package be graded? A stuck name with NO row (the lookup was killed
  # by the outer timeout, crashed, or came back short) or with anything but a concrete
  # result (`error`, or a garbled field) is UNGRADED → fail closed, never read as "not
  # High/Crit". A within-grace package's lookup error does not matter yet: it is not
  # stuck, and it gets graded again every run until it is.
  cs_ungraded=$(printf '%s\n' "$cs_sev" | awk -F'\t' -v s="$cs_stuck_sp" '
    $1 != "" && index(s, " " $1 " ") { g[$1] = 1
      if ($2 !~ /^(negligible|low|medium|high|critical|unknown)$/) e = 1 }
    END { n = split(s, p, " "); for (i = 1; i <= n; i++) if (!(p[i] in g)) e = 1; print e + 0 }')
  if [ "$cs_ungraded" != "0" ]; then
    # Stuck update(s) whose severity could NOT be determined (lookup down/incomplete)
    # → fold into monitor-unreadable: quiet, never a fabricated page, never dropped.
    R_STATE="unreadable"; return
  fi
  # Stuck but confirmed NOT High/Critical (low/medium/unknown severity, lookup OK). Not
  # a CVE page; but a package that has sat past its whole auto-apply window means
  # unattended-upgrades has likely stopped applying anything, which is worth ONE quiet,
  # non-paging card (a liveness signal, no severity named). It clears the usual way when
  # the updates finally apply.
  R_STATE="raised"; R_SEV="warning"
  R_DETAIL="$cs_nstuck pending security update(s) STUCK ${cs_hrs}h; auto-upgrade has not applied them (none of the stuck ones High/Critical). unattended-upgrades may have stopped. pkgs: ${cs_sample}${cs_moretxt}${cs_withintxt}"
  return
}

# --- check 2: reboot pending -------------------------------------------------
# A staged update that needs the reboot is worth a card only when it fixes a
# High/Critical CVE that is not live yet; everything else goes into the hub's weekly
# summary (send_reboot_pending below). A box that cannot be rebooted often would
# otherwise carry a card for every staged update, which only nags. Read-only:
# it reads the flag, dpkg's database, the Livepatch client and needrestart's list mode,
# and restarts nothing.
#
# Sets R_STATE / R_SEV / R_DETAIL for `reboot-security`, plus:
#   RB_FLAG     1 = a reboot is pending: the reboot flag is set, or a kernel newer than
#               the running one is installed (RB_KBEHIND)
#   RB_DECIDED  1 = R_STATE is a real answer (no flag, or every staged package was
#               graded); 0 = it could not tell, so the card is left as it is
#   RB_CHECKED  yes | no (the weekly summary's "not checked")
#   RB_SINCE    first time this box was seen with the flag (epoch seconds)
#   RB_PKGS     the staged package names, space-separated
#   RB_LP       on | off (Livepatch reports the running kernel as supported)
#   RB_COV / RB_UNC  how many High/Critical CVEs are already live / not live (checked only)
#
# What counts as live:
#   - a kernel package (`linux-*`): Livepatch is applied to the RUNNING kernel and lists
#     that CVE among its fixes. No Livepatch, output it cannot read, a kernel it does not
#     support, or a CVE it does not list = not live;
#   - any other package (libc6, dbus, systemd...): `needrestart -b` (list mode) answered
#     and names no service still on the old code. needrestart missing or unreadable = not
#     live. The kernel line of its output is not looked at: the kernel is judged above.
# The kernel is judged from dpkg's database, not only from the flag: with Livepatch on,
# Ubuntu's notify-reboot-required never sets the flag for a linux-* package (it leaves
# the reboot to Livepatch, even when Livepatch has nothing applied), so a box can run
# an old kernel for weeks with no flag. A kernel image is graded over every notice
# between the running version and the installed one (cve-severity.py's third column),
# so a fix that came with an in-between version is counted too. For any other package,
# only the CVEs of the installed version's own notice are counted. A kernel that is
# still not graded REBOOT_UNGRADED_SECS after it was installed is a card anyway.

# Livepatch's JSON, read defensively: the first JSON object in the output (a warning
# line before it is skipped), keys in any case, the running kernel's entry
# (`Running: true`, or the kernel matching `uname -r` when there is no such field), its
# support and patch state, and the CVE ids among its fixes (a string or a list), any
# case, printed uppercase. Anything unexpected prints `off`. Prints `<state>\t<ids>`.
# With a second argument `check` it answers check 9 instead: `ok`, `notenabled`,
# `unread`, or `bad<TAB><why>`.
LP_PARSE_PY=$(cat <<'PYEOF'
import json, re, sys
def low(o):
    if isinstance(o, dict):
        return {str(k).lower(): low(v) for k, v in o.items()}
    if isinstance(o, list):
        return [low(v) for v in o]
    return o
def abi(k):
    m = re.match(r"^(\d+\.\d+\.\d+-\d+)(?:\.\d+)*(-[a-z0-9]+)?", k or "")
    return (m.group(1), m.group(2) or "") if m else None
def running(d, kr):
    st = d.get("status") if isinstance(d, dict) else None
    for e in (st if isinstance(st, list) else []):
        if not isinstance(e, dict):
            continue
        run = e.get("running")
        if run is True or (run is None and kr is not None and abi(str(e.get("kernel") or "")) == kr):
            return e
    return None
def patch_state(e):
    lp = e.get("livepatch") if isinstance(e, dict) else None
    if not isinstance(lp, dict):
        return None, ""
    s = str(lp.get("state") or lp.get("patchstate") or "").strip().lower()
    return lp, (s if re.fullmatch(r"[a-z][a-z-]{0,31}", s) else "")
raw = sys.stdin.read(2000000)
kr = abi(sys.argv[1] if len(sys.argv) > 1 else "")
try:
    d = low(json.JSONDecoder().raw_decode(raw[raw.index("{"):])[0])
except Exception:
    d = None
if len(sys.argv) > 2 and sys.argv[2] == "check":
    try:
        pick = running(d, kr)
        if pick is None:
            print("notenabled" if re.search(r"\bnot enabled\b", raw, re.I) else "unread")
        else:
            kern = re.sub(r"[^A-Za-z0-9._+-]", "", str(pick.get("kernel") or ""))[:64] or "?"
            sup = str(pick.get("supported") or "").strip().lower()
            lp, s = patch_state(pick)
            if sup not in ("", "supported", "unknown"):
                print("bad\tLivepatch does not support the running kernel %s (%s)" % (kern, re.sub(r"[^a-z -]", "", sup)[:32]))
            elif s in ("apply-failed", "kernel-upgrade-required"):
                print("bad\tLivepatch cannot patch the running kernel %s (%s)" % (kern, s))
            elif sup == "unknown":
                print("unread")
            else:
                print("ok")
    except Exception:
        print("unread")
    sys.exit(0)
try:
    pick = running(d, kr)
    state, ids = "off", set()
    lp, s = patch_state(pick)
    sup = str(pick.get("supported") or "").strip().lower() if isinstance(pick, dict) else ""
    if lp is not None and sup in ("", "supported"):
        if s:
            state = s
        if state == "applied":
            fx = lp.get("fixes")
            for it in (fx if isinstance(fx, list) else [fx]):
                if isinstance(it, dict):
                    if it.get("patched") is False:
                        continue
                    it = it.get("name") or json.dumps(it)
                if isinstance(it, str):
                    ids.update(c.upper() for c in re.findall(r"cve-\d{4,}-\d+", it, re.I))
    print(state + "\t" + " ".join(sorted(ids)))
except Exception:
    print("off\t")
PYEOF
)

# Sets LP_RAW to what `<livepatch> status --format json` printed, stdout and stderr
# together (so check 9 can tell "not enabled" from a failed read). Read at most once a
# run: the reboot check and check 9 share it. Direct first; with no JSON back (a snap
# under the unit's NoNewPrivileges prints only an error) the same read-only command runs
# once through SYSTEMD_RUN. A missing systemd-run skips that.
LP_RAW=""; LP_FETCHED=0
livepatch_fetch() {
  [ "$LP_FETCHED" = 1 ] && return 0
  LP_FETCHED=1; LP_RAW=""
  command -v "${LIVEPATCH_CMD%% *}" >/dev/null 2>&1 || return 0
  LP_RAW=$($LP_WRAP $LIVEPATCH_CMD status --format json 2>&1) || :
  case "$LP_RAW" in *'{'*) return 0 ;; esac
  command -v "$SYSTEMD_RUN" >/dev/null 2>&1 || return 0
  lp_sr=$($LP_WRAP "$SYSTEMD_RUN" --quiet --wait --pipe --collect --no-ask-password \
    --unit=nethersec-livepatch-status -p RuntimeMaxSec=20 -p ProtectHome=read-only -p PrivateTmp=yes \
    $LIVEPATCH_CMD status --format json 2>&1) || :
  [ -n "$lp_sr" ] && LP_RAW="$lp_sr"
  return 0
}

# Sets RB_LP_STATE (the running kernel's patch state, or `off`) and RB_LP_FIXES (" "-joined ids).
livepatch_read() {
  RB_LP_STATE="off"; RB_LP_FIXES=""
  command -v python3 >/dev/null 2>&1 || return 0
  livepatch_fetch
  [ -n "$LP_RAW" ] || return 0
  lp_out=$(printf '%s\n' "$LP_RAW" | python3 -I -c "$LP_PARSE_PY" "$KERNEL_RELEASE" 2>/dev/null) || lp_out=""
  lp_state=$(printf '%s' "$lp_out" | head -1 | cut -f1)
  case "$lp_state" in ''|*[!a-z-]*) lp_state="off" ;; esac
  RB_LP_STATE="$lp_state"
  [ "$lp_state" = "applied" ] && RB_LP_FIXES=$(printf '%s' "$lp_out" | head -1 | cut -f2 | tr -cd 'A-Z0-9 -')
  return 0
}

# Sets RB_NR: clean (answered, no service on old code) | dirty | unreadable, and
# RB_NR_SVCS (the services it named). List mode only: it restarts nothing.
needrestart_read() {
  RB_NR="unreadable"; RB_NR_SVCS=""
  command -v "$NEEDRESTART_BIN" >/dev/null 2>&1 || return 0
  nr_out=$($NR_WRAP "$NEEDRESTART_BIN" -b -r l 2>/dev/null)
  nr_rc=$?
  # Cut off by the time limit: what it printed may be partial, so it did not answer.
  [ "$nr_rc" -eq 124 ] && return 0
  # A run that printed no NEEDRESTART- line at all did not answer either.
  printf '%s\n' "$nr_out" | grep -q '^NEEDRESTART-' || return 0
  RB_NR_SVCS=$(printf '%s\n' "$nr_out" | awk '/^NEEDRESTART-SVC:/ { print $2 }' \
    | tr -cd 'A-Za-z0-9@._:\n-' | awk 'NF' | sort -u | tr '\n' ' ' | sed 's/ *$//')
  if [ -n "$RB_NR_SVCS" ]; then RB_NR="dirty"; else RB_NR="clean"; fi
  return 0
}

# Sets RB_KRUN_VER (the running kernel's package version), RB_KNEW_PKG / RB_KNEW_VER (the
# newest installed kernel image with the running one's base version and flavor, e.g.
# linux-image-6.8.0-*-generic) and RB_KBEHIND=1 when that image is newer than the
# running kernel. A running kernel no package owns, or a release it cannot parse, is not
# judged (RB_KBEHIND=0). Read-only.
kernel_behind_read() {
  RB_KRUN_VER=""; RB_KNEW_PKG=""; RB_KNEW_VER=""; RB_KBEHIND=0
  case "$KERNEL_RELEASE" in ''|*[!A-Za-z0-9.+_-]*) return 0 ;; esac
  command -v "$DPKG_QUERY" >/dev/null 2>&1 || return 0
  kb_base=$(printf '%s' "$KERNEL_RELEASE" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-[0-9][0-9]*-[a-z0-9][a-z0-9.+-]*$/\1/p')
  kb_flav=$(printf '%s' "$KERNEL_RELEASE" | sed -n 's/^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*-[0-9][0-9]*-\([a-z0-9][a-z0-9.+-]*\)$/\1/p')
  [ -n "$kb_base" ] && [ -n "$kb_flav" ] || return 0
  RB_KRUN_VER=$("$DPKG_QUERY" -W -f='${db:Status-Abbrev}\t${Version}\n' "linux-image-$KERNEL_RELEASE" 2>/dev/null \
    | awk -F'\t' '$1 ~ /^ii/ && $2 != "" { print $2; exit }')
  [ -n "$RB_KRUN_VER" ] || return 0
  kb_rows=$("$DPKG_QUERY" -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' 'linux-image-[0-9]*' 2>/dev/null \
    | awk -F'\t' -v b="$kb_base" -v f="$kb_flav" '
        $1 ~ /^ii/ && $3 != "" {
          n = $2; pre = "linux-image-" b "-"; suf = "-" f
          if (length(n) <= length(pre) + length(suf)) next
          if (substr(n, 1, length(pre)) != pre || substr(n, length(n) - length(suf) + 1) != suf) next
          if (substr(n, length(pre) + 1, length(n) - length(pre) - length(suf)) !~ /^[0-9]+$/) next
          if ($3 !~ /^[A-Za-z0-9.+~:-]+$/) next
          print $3 "\t" n
        }')
  [ -n "$kb_rows" ] || return 0
  kb_top=$(printf '%s\n' "$kb_rows" | sort -t "$(printf '\t')" -k1,1V | tail -1)
  RB_KNEW_VER=$(printf '%s' "$kb_top" | cut -f1)
  RB_KNEW_PKG=$(printf '%s' "$kb_top" | cut -f2)
  [ -n "$RB_KNEW_VER" ] && [ "$RB_KNEW_VER" != "$RB_KRUN_VER" ] || return 0
  kb_hi=$(printf '%s\n%s\n' "$RB_KRUN_VER" "$RB_KNEW_VER" | sort -V | tail -1)
  [ "$kb_hi" = "$RB_KNEW_VER" ] && RB_KBEHIND=1
  return 0
}

check_reboot_required() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  RB_FLAG=0; RB_DECIDED=1; RB_CHECKED="no"; RB_SINCE=""; RB_PKGS=""; RB_LP="off"; RB_COV=""; RB_UNC=""
  rb_since_f="$STATE_DIR/reboot-pending.since"
  kernel_behind_read
  if [ ! -f "$REBOOT_FLAG" ] && [ "$RB_KBEHIND" != "1" ]; then
    rm -f "$rb_since_f" 2>/dev/null
    return   # nothing staged: ok (resolves an open reboot-security card)
  fi
  RB_FLAG=1; RB_DECIDED=0

  # When this box was first seen with a reboot pending. The first sight seeds it from the
  # flag's mtime (the latest staged install, never later than now), or with no flag from
  # the newer kernel's install time, so a box that was already pending before this
  # version ran does not start at zero days. A garbled or future stamp is seeded again.
  # No clock this run (NOW=0): nothing is written.
  RB_SINCE=""
  [ -f "$rb_since_f" ] && read -r RB_SINCE < "$rb_since_f" 2>/dev/null
  case "$RB_SINCE" in ''|*[!0-9]*) RB_SINCE="" ;; esac
  if [ "$NOW" -gt 0 ] && { [ -z "$RB_SINCE" ] || [ "$RB_SINCE" -le 0 ] || [ "$RB_SINCE" -gt "$NOW" ]; }; then
    if [ -f "$REBOOT_FLAG" ]; then
      rb_m=$(stat -c %Y "$REBOOT_FLAG" 2>/dev/null)
    else
      rb_m=$(stat -c %Y "$DPKG_INFO_DIR/$RB_KNEW_PKG.list" 2>/dev/null)
    fi
    case "$rb_m" in ''|*[!0-9]*) rb_m="$NOW" ;; esac
    { [ "$rb_m" -le 0 ] || [ "$rb_m" -gt "$NOW" ]; } && rb_m="$NOW"
    RB_SINCE="$rb_m"
    put_state "$rb_since_f" "$RB_SINCE"
  fi

  # The staged packages: dpkg names only. Anything else in the file is dropped, never
  # echoed. A newer kernel counts as staged whether or not the flag names it.
  rb_names=""
  if [ -f "${REBOOT_FLAG}.pkgs" ]; then
    rb_names=$(awk '{ print $1 }' "${REBOOT_FLAG}.pkgs" 2>/dev/null | grep -E '^[a-z0-9][a-z0-9+.-]*$' | sort -u)
  fi
  if [ "$RB_KBEHIND" = "1" ]; then
    rb_names=$(printf '%s\n%s\n' "$rb_names" "$RB_KNEW_PKG" | awk 'NF' | sort -u)
  fi
  RB_PKGS=$(printf '%s\n' "$rb_names" | awk 'NF' | tr '\n' ' ' | sed 's/ *$//')
  livepatch_read
  [ "$RB_LP_STATE" = "off" ] || RB_LP="on"
  reboot_grade

  # A newer kernel that still cannot be graded must not stay silent: a big kernel notice
  # grades over many runs, and the feed can be down for days. Once it has waited
  # REBOOT_UNGRADED_SECS since its own install (dpkg's .list mtime; the since stamp when
  # that cannot be read, since a flag can be older or newer than the kernel) it is a card
  # anyway (quiet, like every reboot card). A later run that grades it decides as usual,
  # and resolves the card when nothing is left.
  [ "$RB_DECIDED" != "1" ] && [ "$RB_KBEHIND" = "1" ] && [ "$NOW" -gt 0 ] || return
  rb_kat=$(stat -c %Y "$DPKG_INFO_DIR/$RB_KNEW_PKG.list" 2>/dev/null)
  case "$rb_kat" in ''|*[!0-9]*) rb_kat="" ;; esac
  { [ -z "$rb_kat" ] || [ "$rb_kat" -le 0 ] || [ "$rb_kat" -gt "$NOW" ]; } && rb_kat="$RB_SINCE"
  [ -n "$rb_kat" ] && [ $((NOW - rb_kat)) -ge "$REBOOT_UNGRADED_SECS" ] || return
  R_STATE="raised"; R_SEV="warning"; RB_DECIDED=1
  R_DETAIL="${SOURCE} runs kernel ${KERNEL_RELEASE} (${RB_KRUN_VER}), but ${RB_KNEW_PKG} (${RB_KNEW_VER}) was installed $(( (NOW - rb_kat) / 86400 )) day(s) ago and its CVEs could not be checked yet. Treat it as a security reboot. Livepatch: ${RB_LP_STATE}."
}

# Grades the staged packages for check_reboot_required. Every step that cannot answer
# returns with RB_DECIDED=0: no card, no resolve, and the weekly summary says "not checked".
reboot_grade() {
  [ -n "$rb_names" ] || return
  [ "$CVE_LOOKUP" = "1" ] || return
  command -v "$DPKG_QUERY" >/dev/null 2>&1 || return
  rb_pairs=$(for rb_p in $rb_names; do
    rb_v=$("$DPKG_QUERY" -W -f='${db:Status-Abbrev}\t${Version}\n' "$rb_p" 2>/dev/null \
      | awk -F'\t' '$1 ~ /^ii/ && $2 != "" { print $2; exit }')
    # Not installed any more (an old kernel removed before the reboot): it cannot be
    # booted into, so it is not graded. A kernel image also carries the running kernel's
    # version, so every notice in between is graded, not just the installed one's.
    if [ -n "$rb_v" ]; then
      case "$rb_p" in
        linux-image-[0-9]*)
          if [ -n "$RB_KRUN_VER" ]; then printf '%s\t%s\t%s\n' "$rb_p" "$rb_v" "$RB_KRUN_VER"
          else printf '%s\t%s\n' "$rb_p" "$rb_v"; fi ;;
        *) printf '%s\t%s\n' "$rb_p" "$rb_v" ;;
      esac
    fi
  done)
  [ -n "$rb_pairs" ] || return
  rb_sev=$(printf '%s\n' "$rb_pairs" | HOSTSEC_STATE_DIR="$STATE_DIR" HOSTSEC_CVE_LIST=1 $CVE_WRAP $CVE_CMD 2>/dev/null)
  # Every graded package needs a concrete answer: a missing row, `error` or a garbled
  # result means the list may be incomplete, so the box is not checked.
  rb_want=" $(printf '%s\n' "$rb_pairs" | cut -f1 | tr '\n' ' ')"
  rb_bad=$(printf '%s\n' "$rb_sev" | awk -F'\t' -v s="$rb_want" '
    $1 != "" && index(s, " " $1 " ") { if (NF >= 5 && $2 ~ /^(negligible|low|medium|high|critical|unknown)$/) g[$1] = 1; else e = 1 }
    END { n = split(s, p, " "); for (i = 1; i <= n; i++) if (!(p[i] in g)) e = 1; print e + 0 }')
  [ "$rb_bad" = "0" ] || return

  # needrestart only when a non-kernel package carries a High/Critical fix.
  RB_NR="n/a"; RB_NR_SVCS=""
  rb_need_nr=$(printf '%s\n' "$rb_sev" | awk -F'\t' '$1 !~ /^linux-/ && $5 ~ /CVE-/ { f = 1 } END { print f + 0 }')
  [ "$rb_need_nr" = "1" ] && needrestart_read
  # One pass over the ids (a kernel CVE is listed under every kernel package, so ids are
  # counted once; one not live under ANY package is not live).
  rb_calc=$(printf '%s\n' "$rb_sev" | awk -F'\t' -v s="$rb_want" -v lp="$RB_LP_STATE" -v fixes=" $RB_LP_FIXES " -v nr="$RB_NR" '
    $1 != "" && index(s, " " $1 " ") && NF >= 5 && $5 != "" {
      n = split($5, ids, ",")
      kern = ($1 ~ /^linux-/)
      for (i = 1; i <= n; i++) {
        c = ids[i]
        if (c !~ /^CVE-[0-9][0-9][0-9][0-9][0-9]*-[0-9][0-9]*$/) continue
        all[c] = 1
        live = kern ? (lp == "applied" && index(fixes, " " c " ") > 0) : (nr == "clean")
        if (!live) { unc[c] = 1; up[$1] = 1 }
      }
    }
    END {
      t = 0; for (c in all) t++
      for (c in unc) print "U\t" c
      for (p in up) print "P\t" p
      print "T\t" t
    }')
  rb_total=$(printf '%s\n' "$rb_calc" | awk -F'\t' '$1 == "T" { print $2 }')
  case "$rb_total" in ''|*[!0-9]*) rb_total=0 ;; esac
  rb_ids=$(printf '%s\n' "$rb_calc" | awk -F'\t' '$1 == "U" { print $2 }' | sort)
  rb_upkgs=$(printf '%s\n' "$rb_calc" | awk -F'\t' '$1 == "P" { print $2 }' | sort | tr '\n' ' ' | sed 's/ *$//')
  RB_UNC=$(printf '%s\n' "$rb_ids" | awk 'NF' | wc -l | tr -d ' ')
  RB_COV=$((rb_total - RB_UNC))
  RB_CHECKED="yes"; RB_DECIDED=1
  [ "$RB_UNC" -gt 0 ] || return   # nothing High/Critical waits on the reboot: ok

  rb_top=$(printf '%s\n' "$rb_ids" | head -5 | tr '\n' ' ' | sed 's/ *$//; s/ /, /g')
  rb_more=$((RB_UNC - 5)); rb_moretxt=""
  [ "$rb_more" -gt 0 ] && rb_moretxt=" (+$rb_more more)"
  rb_svctxt=""
  case "$RB_NR" in
    dirty) rb_svctxt=" Services still on the old code: $(printf '%s' "$RB_NR_SVCS" | tr ' ' '\n' | head -6 | tr '\n' ' ' | sed 's/ *$//')." ;;
    unreadable) rb_svctxt=" needrestart could not be read." ;;
  esac
  R_STATE="raised"; R_SEV="warning"
  R_DETAIL="${RB_UNC} High/Critical CVE(s) fixed by a staged update are not live until ${SOURCE} reboots: ${rb_top}${rb_moretxt}. Packages: ${rb_upkgs}. Livepatch: ${RB_LP_STATE}.${rb_svctxt}"
}

# --- reboot-pending data report ---------------------------------------------
# The data behind the hub's weekly "Pending reboots" summary: a `reboot-pending` report
# (info) that the hub stores per box and never turns into a card (docs/report-protocol.md
# has the detail format). Sent when it changes, and at most every REBOOT_REPORT_EVERY
# otherwise; a resolved one once the flag clears. An undelivered report is retried on
# the next run, except one the hub refused for this key (403), which waits for the
# resend interval or a change (data_refused). The FIRST one waits REBOOT_REPORT_ARM
# (default 0) after the detector first runs on the box.
send_reboot_pending() {
  [ "$NOW" -gt 0 ] || return 0
  rp_sent_f="$STATE_DIR/reboot-pending.sent"
  rp_arm_f="$STATE_DIR/reboot-pending.armed"
  rp_arm=""
  [ -f "$rp_arm_f" ] && read -r rp_arm < "$rp_arm_f" 2>/dev/null
  case "$rp_arm" in ''|*[!0-9]*) rp_arm="" ;; esac
  if [ -z "$rp_arm" ] || [ "$rp_arm" -gt "$NOW" ]; then
    rp_arm="$NOW"; put_state "$rp_arm_f" "$rp_arm"
  fi
  rp_ref_f="$STATE_DIR/reboot-pending.refused"
  if [ "$RB_FLAG" != "1" ]; then
    # Nothing stored at the hub (never delivered): nothing to resolve, no refusal to keep.
    [ -f "$rp_sent_f" ] || { rm -f "$rp_ref_f" 2>/dev/null; return 0; }
    data_refused_recently "$rp_ref_f" resolved "$REBOOT_REPORT_EVERY" && return 0
    emit --event reboot-pending --state resolved --severity info --title "Reboot pending"
    if [ "$EMIT_OK" = "1" ]; then
      rm -f "$rp_sent_f" "$rp_ref_f" 2>/dev/null
    elif [ "$EMIT_REFUSED" = "1" ]; then
      data_refused "$rp_ref_f" resolved "the resolved reboot-pending report" "$REBOOT_REPORT_EVERY"
    fi
    return 0
  fi
  [ $((NOW - rp_arm)) -ge "$REBOOT_REPORT_ARM" ] || return 0
  # Fixed key=value tokens with no spaces in a value; the hub reads only these.
  rp_list=$(printf '%s\n' "$RB_PKGS" | tr ' ' '\n' | awk 'NF')
  rp_n=$(printf '%s\n' "$rp_list" | awk 'NF' | wc -l | tr -d ' ')
  rp_pkgs=$(printf '%s\n' "$rp_list" | awk 'NF' | head -12 | tr '\n' ',' | sed 's/,*$//')
  rp_more=$((rp_n - 12)); [ "$rp_more" -lt 0 ] && rp_more=0
  rp_payload="v=1 since=${RB_SINCE:-0} checked=${RB_CHECKED} livepatch=${RB_LP} pkgs=${rp_pkgs:--} more=${rp_more}"
  [ "$RB_CHECKED" = "yes" ] && rp_payload="$rp_payload hc_covered=${RB_COV} hc_uncovered=${RB_UNC}"
  rp_at=0; rp_line=""
  [ -f "$rp_sent_f" ] && { IFS= read -r rp_line < "$rp_sent_f" 2>/dev/null || :; }
  rp_at="${rp_line%% *}"; rp_last="${rp_line#* }"
  case "$rp_at" in ''|*[!0-9]*) rp_at=0 ;; esac
  if [ "$rp_last" = "$rp_payload" ] && [ "$rp_at" -le "$NOW" ] && [ $((NOW - rp_at)) -lt "$REBOOT_REPORT_EVERY" ]; then
    return 0
  fi
  data_refused_recently "$rp_ref_f" "$rp_payload" "$REBOOT_REPORT_EVERY" && return 0
  emit --event reboot-pending --state triggered --severity info --title "Reboot pending" --detail "$rp_payload"
  if [ "$EMIT_OK" = "1" ]; then
    put_state "$rp_sent_f" "$NOW $rp_payload"; rm -f "$rp_ref_f" 2>/dev/null
  elif [ "$EMIT_REFUSED" = "1" ]; then
    data_refused "$rp_ref_f" "$rp_payload" "the reboot-pending report" "$REBOOT_REPORT_EVERY"
  fi
  return 0
}

# --- check 3: SSH auth burst -------------------------------------------------
check_ssh_auth() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  if ! command -v journalctl >/dev/null 2>&1; then
    R_STATE="unreadable"; return
  fi
  ca_last=0
  if [ -f "$STATE_DIR/lastrun" ]; then
    read -r ca_last < "$STATE_DIR/lastrun" 2>/dev/null || ca_last=0
    case "$ca_last" in ''|*[!0-9]*) ca_last=0 ;; esac
  fi
  # First run (no baseline): don't alert on the whole history; just baseline.
  if [ "$ca_last" -eq 0 ]; then
    return
  fi
  # sshd logs under identifier `sshd` (and `sshd-session` on OpenSSH >= 9.8).
  ca_raw=$(journalctl --since "@$ca_last" -t sshd -t sshd-session --no-pager 2>/dev/null)
  if [ $? -ne 0 ]; then
    R_STATE="unreadable"; return
  fi
  ca_fails=$(printf '%s\n' "$ca_raw" \
    | grep -Ec 'Failed password|Invalid user|authentication failure|Connection closed by (invalid|authenticating) user|maximum authentication attempts') \
    || ca_fails=0
  case "$ca_fails" in ''|*[!0-9]*) ca_fails=0 ;; esac
  if [ "$ca_fails" -lt "$SSH_BURST" ]; then
    R_STATE="ok"; return
  fi
  # Best-effort context: top source IP + current fail2ban bans (never fatal).
  ca_ip=$(printf '%s\n' "$ca_raw" | grep -Eo 'from [0-9a-fA-F:.]+' | awk '{print $2}' \
    | sort | uniq -c | sort -rn | head -1 | awk '{printf "%s (%s hits)", $2, $1}')
  ca_ban=""
  if command -v fail2ban-client >/dev/null 2>&1; then
    ca_bn=$(fail2ban-client status sshd 2>/dev/null | awk -F'[[:space:]]+' '/Currently banned/ {print $NF}')
    case "$ca_bn" in ''|*[!0-9]*) : ;; *) ca_ban=", fail2ban banned now: $ca_bn" ;; esac
  fi
  R_STATE="raised"; R_SEV="$SSH_SEVERITY"
  R_DETAIL="${ca_fails} failed SSH logins since last check${ca_ip:+, top ${ca_ip}}${ca_ban}"
}

# --- check 4: application / container error-log rate -------------------------
# Counts ERROR-class lines since the last run from (a) journald priority<=err
# (MINUS all sshd lines; SSH auth is owned by check_ssh_auth; plus a little
# generic scanner chatter) and (b) each running container's docker logs, then
# normalizes to errors/hour. json-file docker logs are NOT in journald, so both
# legs are needed. A source present-but-unreadable downgrades the count to a
# FLOOR (noted in the detail) rather than lying with a 0; if NOTHING is readable
# the check is `unreadable` and (like the others) publishes nothing.
check_log_errors() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  [ "$LOGERR_ENABLE" = "1" ] || return

  # Same shared window clock check_ssh_auth reads; written once at run end.
  cl_last=0
  if [ -f "$STATE_DIR/lastrun" ]; then
    read -r cl_last < "$STATE_DIR/lastrun" 2>/dev/null || cl_last=0
    case "$cl_last" in ''|*[!0-9]*) cl_last=0 ;; esac
  fi
  # First run (no window yet): baseline only, never alert on history.
  [ "$cl_last" -eq 0 ] && return
  cl_win=$((NOW - cl_last)); [ "$cl_win" -lt 1 ] && cl_win=1

  # Benign noise removed so real app errors are not drowned: ALL sshd journal
  # lines (owned by check_ssh_auth) + a little generic scanner chatter. A box
  # adds its own inbound-attack noise via HOSTSEC_LOGERR_EXCLUDE_RE (a mail server:
  # 'NOQUEUE:.*reject'; a web box: ' 4[0-9][0-9] ').
  cl_exclude='sshd(-session)?\[[0-9]+\]|kex_exchange_identification|kex_protocol_error|MaxStartups|Protocol major versions differ|maximum authentication attempts|banner exchange'
  [ -n "${HOSTSEC_LOGERR_EXCLUDE_RE:-}" ] && cl_exclude="$cl_exclude|${HOSTSEC_LOGERR_EXCLUDE_RE}"

  cl_readable=0   # 1 once ANY source is successfully read
  cl_unread=""    # sources present-but-unreadable (→ count is a FLOOR)
  cl_jrnl=0
  cl_dckr=0

  # (a) journald, error priority (0..3), over the window.
  if command -v journalctl >/dev/null 2>&1; then
    cl_jraw=$(journalctl --since "@$cl_last" -p err --no-pager 2>/dev/null)
    if [ $? -eq 0 ]; then
      cl_readable=1
      cl_jrnl=$(printf '%s\n' "$cl_jraw" | grep -Ev '^-- ' | awk 'NF' | grep -Evc "$cl_exclude") || cl_jrnl=0
      case "$cl_jrnl" in ''|*[!0-9]*) cl_jrnl=0 ;; esac
    else
      cl_unread="$cl_unread journald"
    fi
  fi

  # (b) docker container logs since the window start (--since takes a unix ts).
  # No syslog priority here, so match ERROR-class TOKENS; word-boundaried so
  # "errors=0" health lines and "[api.ErrorHandler]" tags do NOT count; plus
  # the common structured shapes (level=error, "level":"error", [error]/[crit]).
  if command -v docker >/dev/null 2>&1; then
    cl_ids=$(docker ps -q 2>/dev/null)
    if [ $? -eq 0 ]; then
      cl_readable=1
      for cl_c in $cl_ids; do
        cl_l=$(docker logs --since "$cl_last" "$cl_c" 2>&1)
        if [ $? -ne 0 ]; then
          cl_unread="$cl_unread docker:${cl_c}"
          continue
        fi
        cl_n=$(printf '%s\n' "$cl_l" | grep -Ev "$cl_exclude" \
          | grep -Eic '\b(error|fatal|panic|exception|traceback|segfault)\b|level=error|"level":"?error|\[error\]|\[crit\]|oom-kill|out of memory') || cl_n=0
        case "$cl_n" in ''|*[!0-9]*) cl_n=0 ;; esac
        cl_dckr=$((cl_dckr + cl_n))
      done
    else
      cl_unread="$cl_unread docker"
    fi
  fi

  # Nothing readable at all → UNKNOWN, never a fabricated 0. A source that is
  # simply ABSENT (no docker, or no journald) is not unreadable; it adds 0.
  if [ "$cl_readable" -eq 0 ]; then
    R_STATE="unreadable"; return
  fi

  cl_total=$((cl_jrnl + cl_dckr))
  cl_rate=$(( cl_total * 3600 / cl_win ))
  cl_partial=""
  [ -n "$cl_unread" ] && cl_partial=" (FLOOR; unreadable:${cl_unread})"

  if [ "$cl_rate" -lt "$LOGERR_BURST" ]; then
    R_STATE="ok"; return
  fi
  R_STATE="raised"; R_SEV="$LOGERR_SEVERITY"
  R_DETAIL="logErrRate1h=${cl_rate}/hr (${cl_total} in ${cl_win}s): journald=${cl_jrnl}, docker=${cl_dckr}${cl_partial}"
}

# --- check 5: write-side applier backstop ------------------------------------
# apply-aged-upgrades.sh owns the GATED pockets (-updates / third-party) that this
# read-only detector does NOT enumerate. If that applier dies, or a hold it set
# sticks forever, those packages go silently unpatched; so this read-only detector
# is their INDEPENDENT backstop (the applier can't be trusted to escalate its own
# death). Entirely gated on the applier's state files existing, so it is inert on a
# box not running the applier; never posts there.
check_apply_backstop() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  ab_hb="$STATE_DIR/apply-heartbeat"
  ab_holds="$STATE_DIR/holds.apply.tsv"
  [ -f "$ab_hb" ] || return   # applier never ran here -> nothing to back up
  # A deliberately paused applier (apply-disabled) is not a fault; and its disable
  # path already released every hold; so don't card a stale heartbeat for it.
  [ -f "${HOSTSEC_APPLY_KILL_FILE:-/etc/nethersec/apply-disabled}" ] && return
  # (a) dead-man's switch: the applier's hourly timer should refresh this heartbeat;
  #     stale past 3h (hourly + generous margin) means it is not completing runs.
  ab_hbt=0
  read -r ab_hbt < "$ab_hb" 2>/dev/null || ab_hbt=0
  case "$ab_hbt" in ''|*[!0-9]*) ab_hbt=0 ;; esac
  if [ "$ab_hbt" -gt 0 ] && [ $((NOW - ab_hbt)) -ge 10800 ]; then
    # A dead applier = the pockets it alone owns stop being patched = a FAILURE, so
    # page (critical), not a quiet card.
    R_STATE="raised"; R_SEV="critical"
    R_DETAIL="release-age applier has not completed a run in $(( (NOW - ab_hbt) / 3600 ))h (heartbeat stale). Packages it holds may be going unpatched; check nethersec-apply-aged.timer/.service."
    return
  fi
  # (b) any hold WE set that is older than the ceiling and still standing.
  if [ -s "$ab_holds" ]; then
    ab_ceil=$(( ${HOSTSEC_APPLY_CEILING_DAYS:-10} * 86400 ))
    ab_stuck=$(awk -F'\t' -v now="$NOW" -v c="$ab_ceil" '($4 ~ /^[0-9]+$/) && (now-$4 >= c){print $1}' "$ab_holds" 2>/dev/null | tr '\n' ' ')
    if [ -n "$(printf '%s' "$ab_stuck" | tr -d ' ')" ]; then
      # A hold stuck past the ceiling = a package held but never patched = a FAILURE
      # → page (critical).
      R_STATE="raised"; R_SEV="critical"
      R_DETAIL="release-age holds stuck past the ceiling: ${ab_stuck}- held but never applied. Investigate the applier."
      return
    fi
  fi
}

# --- check 6: world-writable path to these root-run scripts ------------------
# The units run these scripts as root from /opt/nethersec. A directory on that path
# that any local user can write (and that lacks the sticky bit) lets them rename a
# directory or script and put their own in its place before the next root run; so does
# a world-writable script. install.sh refuses such a path; this catches one that drifts
# back later. Read-only: it stats the path and never changes a mode itself.
check_script_path() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  csp_dir="${HOSTSEC_SCRIPT_PATH:-$SCRIPT_DIR}"
  # Only an absolute path can be walked up to /; the `echo .` fallback above cannot.
  case "$csp_dir" in /*) ;; *) return ;; esac
  csp_bad=""
  csp_d="$csp_dir"; csp_n=0
  while [ "$csp_n" -lt 64 ]; do
    if [ -n "$(find "$csp_d" -maxdepth 0 -type d -perm -0002 ! -perm -1000 2>/dev/null)" ]; then
      csp_bad="$csp_bad $csp_d"
    fi
    [ "$csp_d" = "/" ] && break
    csp_d=$(dirname -- "$csp_d"); csp_n=$((csp_n + 1))
  done
  for csp_f in "$csp_dir"/*.sh "$csp_dir"/*.py; do
    [ -f "$csp_f" ] || continue
    if [ -n "$(find "$csp_f" -maxdepth 0 -perm -0002 2>/dev/null)" ]; then
      csp_bad="$csp_bad $csp_f"
    fi
  done
  [ -n "$csp_bad" ] || return
  R_STATE="raised"; R_SEV="warning"
  R_DETAIL="world-writable on the path of the root-run security scripts:${csp_bad}. Any local user could replace a script before the next root run. Fix: chmod o-w on each, and keep /opt/nethersec owned by root."
}

# --- check 7: third-party updates nothing installs ---------------------------
# Check 1 reads only the distro's security pocket. unattended-upgrades installs only
# distro origins, and the release-age applier ships in dry-run, so a package from a
# vendor's own apt repo (Docker's or another vendor's) waits forever and
# nothing says so. Some vendors publish fixes without a CVE, so no advisory feed
# matches them either.
# This check lists every installed package whose candidate comes from a non-distro
# origin (apt-introspect.py, the applier's own reader, which also sees held packages),
# runs one clock per package from when it was first seen behind, and raises ONE quiet
# card per box once any of them has waited past HOSTSEC_THIRDPARTY_GRACE_SECS. A new
# vendor release does not restart the clock: the package has been behind since then.
# A read that fails changes nothing (folded into monitor-unreadable).
check_thirdparty_updates() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  ct_f="$STATE_DIR/first-seen.thirdparty.tsv"
  if [ "$THIRDPARTY_ENABLE" != "1" ]; then
    rm -f "$ct_f" 2>/dev/null
    return
  fi
  # A failed clock read would stamp every package as first seen at the epoch.
  if [ "$NOW" -le 0 ]; then R_STATE="unreadable"; return; fi
  if ! ct_rows=$($INTROSPECT_CMD 2>/dev/null); then R_STATE="unreadable"; return; fi
  # name<TAB>candidate for each upgradable package from a non-distro origin.
  ct_pending=$(printf '%s\n' "$ct_rows" | awk -F'\t' -v re="$DISTRO_ORIGIN_RE" -v ign=" $THIRDPARTY_IGNORE " '
    NF >= 4 && $1 != "" && $2 != "" && $4 !~ re && index(ign, " " $1 " ") == 0 { print $1 "\t" $2 }' | sort -u)
  if [ -z "$ct_pending" ]; then
    rm -f "$ct_f" 2>/dev/null
    return
  fi
  # Keep each package's first-seen time; anything no longer pending drops out.
  ct_new=$(printf '%s\n' "$ct_pending" | awk -F'\t' -v now="$NOW" -v f="$ct_f" '
    BEGIN { while ((getline l < f) > 0) { split(l, a, "\t"); if (a[2] ~ /^[0-9]+$/ && a[2] + 0 <= now) seen[a[1]] = a[2] } }
    $1 != "" { print $1 "\t" (($1 in seen) ? seen[$1] : now) "\t" $2 }')
  put_state "$ct_f" "$ct_new"
  ct_late=$(printf '%s\n' "$ct_new" | awk -F'\t' -v now="$NOW" -v g="$THIRDPARTY_GRACE_SECS" '
    $2 ~ /^[0-9]+$/ && now - $2 >= g { print $1 "\t" $3 "\t" int((now - $2) / 86400) }')
  [ -n "$ct_late" ] || return
  ct_list=""; ct_n=0
  ct_tab=$(printf '\t')
  while IFS="$ct_tab" read -r ct_p ct_c ct_d; do
    [ -n "$ct_p" ] || continue
    ct_n=$((ct_n + 1))
    [ "$ct_n" -le 8 ] || continue
    ct_i=$("$DPKG_QUERY" -W -f='${db:Status-Abbrev}\t${Version}\n' "$ct_p" 2>/dev/null \
      | awk -F'\t' '$1 ~ /^ii/ && $2 != "" { print $2; exit }')
    ct_list="${ct_list}${ct_list:+, }${ct_p} ${ct_i:-?} -> ${ct_c} (${ct_d}d)"
  done <<EOF
$ct_late
EOF
  [ "$ct_n" -le 8 ] || ct_list="$ct_list, and $((ct_n - 8)) more"
  R_STATE="raised"; R_SEV="warning"
  R_DETAIL="${ct_n} package(s) from vendor apt repos have had a newer version for over $((THIRDPARTY_GRACE_SECS / 86400)) days and are still not installed: ${ct_list}. Unattended-upgrades installs only distro packages, and the release-age applier only installs them when it is live. Check the vendor's notes, then: apt-get install --only-upgrade <package>."
}

# --- check 8: Docker live-restore --------------------------------------------
# Without live-restore, a dockerd or containerd restart stops every container, so a
# Docker package upgrade (the live applier installs them once they age in) is an
# outage on that box. install.sh --with-applier runs docker-live-restore.sh; this cards
# a box that lacks it, say after a rewritten daemon.json. Read-only: one `docker info`. Inert where Docker is not installed; a daemon that does not answer
# reads as unreadable, never as "off".
check_docker_live_restore() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  [ "$LIVE_RESTORE_ENABLE" = "1" ] || return
  command -v "$DOCKER_CMD" >/dev/null 2>&1 || return
  if ! dl_state=$($DL_WRAP "$DOCKER_CMD" info -f '{{.LiveRestoreEnabled}}' 2>/dev/null); then
    R_STATE="unreadable"; return
  fi
  case "$dl_state" in
    true) return ;;
    false) ;;
    *) R_STATE="unreadable"; return ;;
  esac
  R_STATE="raised"; R_SEV="warning"
  R_DETAIL="Docker live-restore is off, so a Docker or containerd upgrade or restart stops every container on this box. Turn it on (no container restarts): sudo bash $SCRIPT_DIR/docker-live-restore.sh"
}

# --- checks 9-12: box drift ---------------------------------------------------
# Settings that are turned on once and that nothing else re-checks: nothing would say
# if Livepatch, the IP-options drop or key-only SSH went away, or a new port opened.
# Each is quiet, raised once, and resolved once it is fixed. A read that fails changes
# nothing and folds into monitor-unreadable.

# Check 9: Livepatch installed, enabled, supporting the running kernel and patching it.
# Shares the reboot check's single Livepatch read.
check_livepatch() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  [ "$LIVEPATCH_CHECK" = "1" ] || return
  if ! command -v "${LIVEPATCH_CMD%% *}" >/dev/null 2>&1; then
    R_STATE="raised"
    R_DETAIL="The Livepatch client is not installed, so kernel fixes wait for a reboot. Turn it on through Ubuntu Pro, with no token on the command line: sudo pro attach (if the box is not attached yet; it shows a code to confirm in a browser), then sudo pro enable livepatch (it installs the client)"
    return
  fi
  command -v python3 >/dev/null 2>&1 || { R_STATE="unreadable"; return; }
  livepatch_fetch
  lc_out=$(printf '%s\n' "$LP_RAW" | python3 -I -c "$LP_PARSE_PY" "$KERNEL_RELEASE" check 2>/dev/null) || lc_out=""
  lc_out=$(printf '%s' "$lc_out" | head -n 1)
  case "$lc_out" in
    ok) return ;;
    notenabled)
      R_STATE="raised"
      R_DETAIL="Livepatch is installed but not enabled, so kernel fixes wait for a reboot. Turn it on through Ubuntu Pro, with no token on the command line: sudo pro attach (if the box is not attached yet; it shows a code to confirm in a browser), then sudo pro enable livepatch" ;;
    bad*)
      lc_why=$(printf '%s' "$lc_out" | cut -s -f2 | tr -cd 'A-Za-z0-9 ._()+-')
      [ -n "$lc_why" ] || { R_STATE="unreadable"; return; }
      R_STATE="raised"
      R_DETAIL="${lc_why}, so kernel fixes wait for a reboot. Check: canonical-livepatch status" ;;
    *) R_STATE="unreadable" ;;
  esac
}

# Check 10: the CVE-2026-98432 mitigation (ipv4-options-drop.sh) still loaded and enabled
# at boot. Its --check exits 1 with a NOT line when it is off; any other failure (no
# root, an nft that does not answer, a timeout) is a failed read, never "off".
check_ipv4_options_drop() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  [ "$IPOPT_CHECK" = "1" ] || return
  io_out=$($DL_WRAP $IPOPT_CMD --check 2>&1); io_rc=$?
  [ "$io_rc" -eq 0 ] && return
  io_off=$(printf '%s\n' "$io_out" | grep -E 'NOT loaded|NOT enabled|nft is not installed' \
    | sed 's/^ipv4-options-drop: //; s/ Turn it on:.*//' | head -n 3 | tr '\n' ' ')
  if [ "$io_rc" -ne 1 ] || [ -z "$io_off" ]; then R_STATE="unreadable"; return; fi
  R_STATE="raised"
  R_DETAIL="The IP-options drop (the CVE-2026-98432 mitigation) is off: ${io_off}Turn it on (restarts nothing): sudo bash $SCRIPT_DIR/ipv4-options-drop.sh"
}

# Check 11: sshd refuses passwords. `sshd -T` prints the settings sshd would run with.
# Keyboard-interactive with PAM asks for the password as well, so it counts too.
# With socket activation (Ubuntu 24.04's default) sshd has not started yet after a boot,
# so /run/sshd does not exist and `sshd -T` refuses to run. `sshd -G` prints the same
# settings without that check, so it is the fallback.
check_sshd_passwords() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
  [ "$SSHD_CHECK" = "1" ] || return
  command -v "$SSHD_CMD" >/dev/null 2>&1 || return   # no sshd here
  if ! sp_cfg=$($DL_WRAP "$SSHD_CMD" -T 2>/dev/null) && ! sp_cfg=$($DL_WRAP "$SSHD_CMD" -G 2>/dev/null); then
    R_STATE="unreadable"; return
  fi
  sp_pw=$(printf '%s\n' "$sp_cfg" | awk '$1 == "passwordauthentication" { print $2; exit }')
  sp_kbd=$(printf '%s\n' "$sp_cfg" | awk '$1 == "kbdinteractiveauthentication" || $1 == "challengeresponseauthentication" { print $2; exit }')
  sp_pam=$(printf '%s\n' "$sp_cfg" | awk '$1 == "usepam" { print $2; exit }')
  case "$sp_pw" in yes|no) ;; *) R_STATE="unreadable"; return ;; esac
  sp_why=""
  [ "$sp_pw" = "yes" ] && sp_why="passwordauthentication yes"
  if [ "$sp_kbd" = "yes" ] && [ "$sp_pam" = "yes" ]; then
    sp_why="${sp_why}${sp_why:+, and }kbdinteractiveauthentication yes with usepam yes"
  fi
  [ -n "$sp_why" ] || return
  R_STATE="raised"
  R_DETAIL="sshd accepts password logins (${sp_why}). Sign in with keys only: set PasswordAuthentication no and KbdInteractiveAuthentication no. sshd keeps the first value it reads, and it reads /etc/ssh/sshd_config.d before sshd_config, so look there first: sudo grep -ri -e passwordauthentication -e kbdinteractive /etc/ssh/sshd_config.d /etc/ssh/sshd_config. Then: sudo sshd -t && sudo systemctl reload ssh"
}

# Check 12: every socket on a non-loopback address is in this box's allowlist. The same
# filter as firewall-snapshot.sh's listener section, which prints today's allowlist line.
# A Docker port published without docker-proxy has no socket to list, so a firewall
# in front of the box is still worth checking on its own.
check_listeners() {
  R_STATE="ok"; R_SEV="warning"; R_DETAIL=""; R_KEY=""
  [ -n "$LISTEN_ALLOW" ] || return
  if ! cn_out=$($DL_WRAP $SS_CMD -Htulnp 2>/dev/null); then R_STATE="unreadable"; return; fi
  # One "<proto>/<address>:<port> (<process>)" line per socket not allowed.
  cn_new=$(printf '%s\n' "$cn_out" | awk -v allow="$LISTEN_ALLOW" '
    # "<address>:<port>" -> A, P (split at the last colon: IPv6 addresses hold colons)
    function ap(s) { if (!match(s, /:[^:]*$/)) return 0; A = substr(s, 1, RSTART - 1); P = substr(s, RSTART + 1); return A != "" && P != "" }
    BEGIN {
      n = split(allow, t, /[ \t,]+/)
      for (i = 1; i <= n; i++) {
        s = index(t[i], "/")
        if (s < 2 || !ap(substr(t[i], s + 1))) continue
        k++; wp[k] = substr(t[i], 1, s - 1); wa[k] = A; wo[k] = P
      }
    }
    NF >= 5 && $5 !~ /^(127\.|\[::1\]|::1)/ {
      if (!ap($5)) next
      for (i = 1; i <= k; i++) if (wp[i] == $1 && (wa[i] == "*" || wa[i] == A) && (wo[i] == "*" || wo[i] == P)) next
      proc = ""
      if (match($0, /users:\(\("[^"]*"/)) { proc = substr($0, RSTART + 9, RLENGTH - 10); gsub(/[^A-Za-z0-9._@-]/, "", proc) }
      print $1 "/" $5 (proc != "" ? " (" proc ")" : "")
    }' | sort -u)
  [ -n "$cn_new" ] || return
  cn_n=$(printf '%s\n' "$cn_new" | awk 'NF' | wc -l | tr -d ' ')
  cn_list=$(printf '%s\n' "$cn_new" | head -n 8 | awk 'NF { printf "%s%s", (n++ ? ", " : ""), $0 }')
  [ "$cn_n" -le 8 ] || cn_list="$cn_list, and $((cn_n - 8)) more"
  R_KEY=$(printf '%s\n' "$cn_new" | sed 's/ (.*//' | cksum | awk '{ print $1 }')
  R_STATE="raised"
  R_DETAIL="${cn_n} socket(s) listen on a non-loopback address but are not in this box's HOSTSEC_LISTEN_ALLOW: ${cn_list}. If one is expected, add its <proto>/<address>:<port> to HOSTSEC_LISTEN_ALLOW in /etc/nethersec/report.env. If not, stop it or bind it to 127.0.0.1."
}

# --- check 13: container OS packages -------------------------------------------
# Not a card here (see the header). Sends the source packages of each running
# container that publishes a port, or shares the host network, as one
# `container-packages` data report (info), for the hub to match against OSV.
# Files are streamed out with `docker cp` into `tar -xO`: nothing runs inside the
# container, an image with no shell or package tool still works, and nothing is
# written to disk. A `docker ps` that fails folds into monitor-unreadable; a
# container that cannot be inspected is skipped this run and the hub keeps what
# it last stored. A list is sent when it changes and at most every
# CTRPKG_REPORT_EVERY otherwise; a resolved report once the container is gone. An
# undelivered one is retried on the next run, except one the hub refused for this key
# (403), which waits for CTRPKG_REPORT_EVERY or a change (data_refused). The FIRST lists
# wait CTRPKG_ARM (default 0) after the detector first runs on the box.
CP_UNREADABLE=0
CP_POSTS=0
CP_OK=0

# One file or directory of a container, on stdout. Fails when the path is missing or
# the copy does not finish (tar refuses an empty or cut archive). The archive is
# capped, so a planted huge file costs a bounded read.
ctr_file() {
  # $1=container id  $2=path
  $DL_WRAP "$DOCKER_CMD" cp -L "$1:$2" - 2>/dev/null | head -c 33554432 | "$TAR_CMD" -xOf - 2>/dev/null
}

# dpkg status (or distroless status.d) on stdin -> `source@version` per installed
# package. A binNMU's source version comes from `Source: name (version)`.
ctrpkg_dpkg() {
  awk '
    function flush() {
      if (pkg != "" && ver != "" && (st == "" || st ~ / ok installed$/)) {
        s = src; sv = ver
        if (s == "") s = pkg
        else if (match(s, /\(.*\)/)) { sv = substr(s, RSTART + 1, RLENGTH - 2); s = substr(s, 1, RSTART - 1) }
        gsub(/[ \t]/, "", s); gsub(/[ \t]/, "", sv)
        print s "@" sv
      }
      pkg = ""; ver = ""; src = ""; st = ""
    }
    /^Package:/ { flush(); pkg = $2; next }
    /^Status:/  { st = $0; sub(/^Status:[ \t]*/, "", st); next }
    /^Version:/ { ver = $2; next }
    /^Source:/  { src = $0; sub(/^Source:[ \t]*/, "", src); next }
    /^[ \t]*$/  { flush() }
    END { flush() }' | grep -E '^[A-Za-z0-9][A-Za-z0-9+._-]*@[A-Za-z0-9][A-Za-z0-9.+~:_-]*$' | sort -u
}

# apk installed db on stdin -> `origin@version` per package (OSV keys Alpine on the origin).
ctrpkg_apk() {
  awk '
    function flush() { if (p != "" && v != "") print ((o != "") ? o : p) "@" v; p = ""; v = ""; o = "" }
    /^P:/ { p = substr($0, 3); next }
    /^V:/ { v = substr($0, 3); next }
    /^o:/ { o = substr($0, 3); next }
    /^[ \t]*$/ { flush() }
    END { flush() }' | grep -E '^[A-Za-z0-9][A-Za-z0-9+._-]*@[A-Za-z0-9][A-Za-z0-9.+~:_-]*$' | sort -u
}

# A KEY=value line of os-release, unquoted and cut to a safe charset.
osrel_value() {
  # $1=os-release text  $2=key  $3=tr charset
  printf '%s\n' "$1" | awk -F= -v k="$2" '$1 == k { v = substr($0, length(k) + 2); gsub(/["'\'']/, "", v); print v; exit }' \
    | tr -cd "$3" | cut -c1-32
}

post_ctrpkg() {
  # $1=state  then the transport flags (--detail ...)
  # CP_OK: delivered. CP_REFUSED: the hub refused it for this key (HTTP 403).
  CP_OK=0; CP_REFUSED=0
  pc_state="$1"; shift
  # The hub did not answer earlier in this run: the list waits for the next run.
  if [ "$HUB_DOWN" = 1 ]; then DEFERRED=$((DEFERRED + 1)); return 0; fi
  CP_POSTS=$((CP_POSTS + 1))
  [ -n "$GROUP" ] && set -- --group "$GROUP" "$@"
  sh "$REPORT" --kind security --source "$SOURCE" --event container-packages --state "$pc_state" \
    --severity info --title "Container packages" "$@" >/dev/null 2>&1
  pc_rc=$?
  if [ "$pc_rc" -eq 0 ]; then
    CP_OK=1
  elif [ "$pc_rc" -eq 4 ]; then
    CP_REFUSED=1
  else
    [ "$pc_rc" -eq 3 ] && HUB_DOWN=1
    log "container package list not delivered (source=$SOURCE, $pc_state)"
  fi
}

send_container_packages() {
  CP_UNREADABLE=0
  [ "$CTRPKG_ENABLE" = "1" ] || return 0
  command -v "$DOCKER_CMD" >/dev/null 2>&1 || return 0
  [ "$NOW" -gt 0 ] || return 0
  cp_dir="$STATE_DIR/ctrpkg"
  if ! mkdir -p "$cp_dir" 2>/dev/null; then log "cannot create $cp_dir"; return 0; fi
  cp_arm=""
  [ -f "$cp_dir/armed" ] && read -r cp_arm < "$cp_dir/armed" 2>/dev/null
  case "$cp_arm" in ''|*[!0-9]*) cp_arm="" ;; esac
  if [ -z "$cp_arm" ] || [ "$cp_arm" -gt "$NOW" ]; then
    cp_arm="$NOW"; put_state "$cp_dir/armed" "$cp_arm"
  fi
  [ $((NOW - cp_arm)) -ge "$CTRPKG_ARM" ] || return 0
  # `|` separates the fields: a port list has spaces in it, and an empty field stays put.
  if ! cp_rows=$($DL_WRAP "$DOCKER_CMD" ps --no-trunc --format '{{.ID}}|{{.Names}}|{{.Networks}}|{{.Ports}}' 2>/dev/null); then
    CP_UNREADABLE=1; return 0
  fi
  cp_start=$(date +%s 2>/dev/null || echo 0)
  cp_seen=" "; cp_left=0
  while IFS='|' read -r cp_id cp_names cp_nets cp_ports; do
    [ -n "$cp_id" ] || continue
    # Published: a port bound on the host (even to loopback, behind a proxy it still
    # serves the internet), or the host's own network.
    case "$cp_ports" in *'->'*) ;; *) [ "$cp_nets" = "host" ] || continue ;; esac
    cp_name="${cp_names%%,*}"
    case "$cp_name" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9_.-]*) continue ;; esac
    # Seen before any skip below, so a container this run did not get to is never
    # reported gone.
    cp_seen="$cp_seen$cp_name "
    if ! cp_insp=$($DL_WRAP "$DOCKER_CMD" inspect -f '{{.Config.Image}} {{.Image}}' "$cp_id" 2>/dev/null); then
      log "container $cp_name: inspect failed; skipped this run"; continue
    fi
    cp_ref="${cp_insp%% *}"; cp_iid="${cp_insp##* }"; cp_iid="${cp_iid#sha256:}"
    case "$cp_ref" in ''|*[!A-Za-z0-9._/:@-]*) log "container $cp_name: unusable image reference; skipped"; continue ;; esac
    case "$cp_iid" in ''|*[!0-9a-f]*) log "container $cp_name: unusable image id; skipped"; continue ;; esac
    cp_f="$cp_dir/$cp_name.sent"
    cp_at=0; cp_lcid=""; cp_liid=""; cp_lsum=""; cp_lpm=""
    [ -f "$cp_f" ] && read -r cp_at cp_lcid cp_liid cp_lsum cp_lpm < "$cp_f" 2>/dev/null
    case "$cp_at" in ''|*[!0-9]*) cp_at=0 ;; esac
    cp_fresh=0
    [ "$cp_at" -le "$NOW" ] && [ $((NOW - cp_at)) -lt "$CTRPKG_REPORT_EVERY" ] && cp_fresh=1
    # Same container on the same image, sent lately: nothing to read. An image with no
    # package database is read again each run, so a failed copy does not hide one for
    # a day.
    if [ "$cp_fresh" = "1" ] && [ "$cp_lcid" = "$cp_id" ] && [ "$cp_liid" = "$cp_iid" ] && [ "$cp_lpm" != "none" ]; then
      continue
    fi
    # A list the hub refused for this key lately (HTTP 403, see data_refused): the same
    # skip, read from that record ("<at> <id> <iid> <sum> <pm>", like the .sent file).
    cp_rf="$cp_dir/$cp_name.refused"
    cp_rat=0; cp_rcid=""; cp_riid=""; cp_rsum=""; cp_rpm=""
    [ -f "$cp_rf" ] && read -r cp_rat cp_rcid cp_riid cp_rsum cp_rpm < "$cp_rf" 2>/dev/null
    case "$cp_rat" in ''|*[!0-9]*) cp_rat=0 ;; esac
    cp_rfresh=0
    [ "$cp_rat" -gt 0 ] && [ "$cp_rat" -le "$NOW" ] && [ $((NOW - cp_rat)) -lt "$CTRPKG_REPORT_EVERY" ] && cp_rfresh=1
    if [ "$cp_rfresh" = "1" ] && [ "$cp_rcid" = "$cp_id" ] && [ "$cp_riid" = "$cp_iid" ] && [ "$cp_rpm" != "none" ]; then
      continue
    fi
    if [ "$CP_POSTS" -ge "$CTRPKG_MAX_POSTS" ] || [ $(( $(date +%s 2>/dev/null || echo 0) - cp_start )) -ge "$CTRPKG_BUDGET" ]; then
      cp_left=$((cp_left + 1)); continue
    fi
    cp_built=$($DL_WRAP "$DOCKER_CMD" image inspect -f '{{.Created}}' "$cp_iid" 2>/dev/null | sed 's/\.[0-9]*//')
    # An empty date would read as today, so only a real one is converted.
    if [ -n "$cp_built" ]; then cp_built=$(date -u -d "$cp_built" +%s 2>/dev/null) || cp_built=""; fi
    case "$cp_built" in ''|*[!0-9]*) cp_built=0 ;; esac
    cp_os=$(ctr_file "$cp_id" /etc/os-release) || cp_os=$(ctr_file "$cp_id" /usr/lib/os-release) || cp_os=""
    cp_osid=$(osrel_value "$cp_os" ID 'a-z0-9._-')
    cp_osver=$(osrel_value "$cp_os" VERSION_ID 'A-Za-z0-9._-')
    cp_pm=none; cp_list=""
    if cp_db=$(ctr_file "$cp_id" /var/lib/dpkg/status); then cp_list=$(printf '%s\n' "$cp_db" | ctrpkg_dpkg); fi
    if [ -z "$cp_list" ] && cp_db=$(ctr_file "$cp_id" /var/lib/dpkg/status.d); then cp_list=$(printf '%s\n' "$cp_db" | ctrpkg_dpkg); fi
    [ -n "$cp_list" ] && cp_pm=dpkg
    if [ -z "$cp_list" ] && cp_db=$(ctr_file "$cp_id" /lib/apk/db/installed); then
      cp_list=$(printf '%s\n' "$cp_db" | ctrpkg_apk); [ -n "$cp_list" ] && cp_pm=apk
    fi
    cp_db=""
    cp_n=$(printf '%s\n' "$cp_list" | awk 'NF' | wc -l | tr -d ' ')
    cp_pkgs=$(printf '%s\n' "$cp_list" | awk 'NF' | head -n "$CTRPKG_MAX_PKGS" | tr '\n' ',' | sed 's/,*$//')
    cp_more=$((cp_n - CTRPKG_MAX_PKGS)); [ "$cp_more" -lt 0 ] && cp_more=0
    # Fixed key=value tokens with no spaces in a value; the hub reads only these.
    cp_payload="v=1 ctr=$cp_name img=$cp_ref iid=$(printf '%s' "$cp_iid" | cut -c1-12) built=$cp_built os=${cp_osid:--} osver=${cp_osver:--} pm=$cp_pm more=$cp_more pkgs=${cp_pkgs:--}"
    cp_sum=$(printf '%s' "$cp_payload" | cksum | awk '{ print $1 }')
    if [ "$cp_fresh" = "1" ] && [ "$cp_lsum" = "$cp_sum" ]; then
      # Unchanged (recreated from the same image, or no package database again).
      put_state "$cp_f" "$cp_at $cp_id $cp_iid $cp_sum $cp_pm"
      continue
    fi
    if [ "$cp_rfresh" = "1" ] && [ "$cp_rsum" = "$cp_sum" ]; then
      # The same list the hub refused lately: keep waiting (the refusal keeps its time).
      put_state "$cp_rf" "$cp_rat $cp_id $cp_iid $cp_sum $cp_pm"
      continue
    fi
    post_ctrpkg triggered --detail "$cp_payload"
    if [ "$CP_OK" = "1" ]; then
      put_state "$cp_f" "$NOW $cp_id $cp_iid $cp_sum $cp_pm"; rm -f "$cp_rf" 2>/dev/null
    elif [ "$CP_REFUSED" = "1" ]; then
      data_refused "$cp_rf" "$cp_id $cp_iid $cp_sum $cp_pm" "the package list of container $cp_name" "$CTRPKG_REPORT_EVERY"
    fi
  done <<EOF
$cp_rows
EOF
  # Gone (stopped, removed, or no longer publishing a port): the hub drops its list.
  for cp_f in "$cp_dir"/*.sent; do
    [ -f "$cp_f" ] || continue
    cp_name=$(basename "$cp_f" .sent)
    case "$cp_seen" in *" $cp_name "*) continue ;; esac
    cp_rf="$cp_dir/$cp_name.refused"
    data_refused_recently "$cp_rf" resolved "$CTRPKG_REPORT_EVERY" && continue
    if [ "$CP_POSTS" -ge "$CTRPKG_MAX_POSTS" ]; then cp_left=$((cp_left + 1)); continue; fi
    post_ctrpkg resolved --detail "v=1 ctr=$cp_name"
    if [ "$CP_OK" = "1" ]; then
      rm -f "$cp_f" "$cp_rf" 2>/dev/null
    elif [ "$CP_REFUSED" = "1" ]; then
      data_refused "$cp_rf" resolved "the resolved package list of container $cp_name" "$CTRPKG_REPORT_EVERY"
    fi
  done
  # A refused list of a container that is gone and was never stored: nothing to resolve.
  for cp_rf in "$cp_dir"/*.refused; do
    [ -f "$cp_rf" ] || continue
    cp_name=$(basename "$cp_rf" .refused)
    case "$cp_seen" in *" $cp_name "*) continue ;; esac
    [ -f "$cp_dir/$cp_name.sent" ] || rm -f "$cp_rf" 2>/dev/null
  done
  [ "$cp_left" -gt 0 ] && log "container package lists: $cp_left left for the next run"
  return 0
}

# --- run the checks ----------------------------------------------------------
check_security_updates
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE security-updates" ;;
  *)
    transition "security-updates" "$R_STATE" "$R_SEV" "Security updates stuck" "$R_DETAIL"
    # One-shot QUIET "done" note when a tracked episode cleared with a High/Critical
    # in it. An `info` report is a note in the hub's status channel with no card, so it
    # never pages and never lingers as an open alert needing manual resolution.
    if [ "$R_DONE" = "1" ]; then
      emit --event security-updates-applied --state triggered --severity info \
        --title "Security updates applied" --detail "$R_DONE_DETAIL"
    fi ;;
esac

check_reboot_required
# Not decided (a lookup that could not finish): no card and no resolve, never a page on
# uncertainty. It is not folded into monitor-unreadable either: the weekly summary says
# "not checked" for the box instead.
if [ "$RB_DECIDED" = "1" ]; then
  transition "reboot-security" "$R_STATE" "$R_SEV" "Reboot needed for a security fix" "$R_DETAIL"
fi
send_reboot_pending

check_ssh_auth
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE ssh-auth" ;;
  *) transition "ssh-auth-burst" "$R_STATE" "$R_SEV" "SSH auth burst" "$R_DETAIL" ;;
esac

check_log_errors
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE log-errors" ;;
  *) transition "log-error-rate" "$R_STATE" "$R_SEV" "Application error-log burst" "$R_DETAIL" ;;
esac

# Backstop the write-side applier (inert unless it has run on this box).
check_apply_backstop
transition "apply-backstop" "$R_STATE" "$R_SEV" "Release-age applier backstop" "$R_DETAIL"

check_script_path
transition "script-path-writable" "$R_STATE" "$R_SEV" "Security scripts on a world-writable path" "$R_DETAIL"

check_thirdparty_updates
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE thirdparty-updates" ;;
  *) transition "thirdparty-updates" "$R_STATE" "$R_SEV" "Vendor package updates not installed" "$R_DETAIL" ;;
esac

check_docker_live_restore
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE docker-live-restore" ;;
  *) transition "docker-live-restore" "$R_STATE" "$R_SEV" "Docker live-restore off" "$R_DETAIL" ;;
esac

check_livepatch
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE livepatch" ;;
  *) transition "livepatch-off" "$R_STATE" "$R_SEV" "Livepatch not running" "$R_DETAIL" ;;
esac

check_ipv4_options_drop
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE ipv4-options-drop" ;;
  *) transition "ipv4-options-drop-off" "$R_STATE" "$R_SEV" "IP-options drop off" "$R_DETAIL" ;;
esac

check_sshd_passwords
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE sshd" ;;
  *) transition "ssh-password-auth" "$R_STATE" "$R_SEV" "SSH accepts passwords" "$R_DETAIL" ;;
esac

check_listeners
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE listeners" ;;
  *) transition "unexpected-listener" "$R_STATE" "$R_SEV" "Unexpected listener" "$R_DETAIL" "$R_KEY" ;;
esac

# Not a card: the package lists of published containers, for the hub to match.
send_container_packages
[ "$CP_UNREADABLE" = "1" ] && UNREADABLE="$UNREADABLE container-packages"

# --- aggregate "monitor unreadable" (one card, never a false all-clear) ------
if [ -n "$UNREADABLE" ]; then
  transition "monitor-unreadable" "raised" "warning" "Host security monitor unreadable" \
    "could not read:${UNREADABLE}. Its signal is UNKNOWN this run (not clear)."
else
  transition "monitor-unreadable" "ok" "warning" "Host security monitor unreadable" ""
fi

# --- record the run clock (for check 3's window) + report overflow -----------
# `unreadable` names the checks that could not read this run, for nethersec-status.sh.
put_state "$STATE_DIR/unreadable" "${UNREADABLE# }"
printf '%s\n' "$NOW" > "$STATE_DIR/lastrun" 2>/dev/null || log "lastrun write failed"
if [ "$OVERFLOW" -gt 0 ]; then
  log "per-run post cap ($MAX_POSTS) hit; $OVERFLOW report(s) suppressed this run"
fi
if [ "$DEFERRED" -gt 0 ]; then
  log "the hub did not answer; $DEFERRED more report(s) wait for the next run"
fi

exit 0
