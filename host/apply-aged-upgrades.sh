#!/usr/bin/env sh
# apply-aged-upgrades.sh: the WRITE-side release-age gate for an Ubuntu server.
# The read-only twin of security-report.sh: same fail-safe envelope (exit 0,
# shared kill switch, per-event throttle, unreadable-is-never-done), but this one
# MUTATES the box, so every guard is stricter.
#
# WHAT IT DOES (docs/host/applier.md has the long version):
#   A supply-chain "release-age grace", the apt analog of npm's minimumReleaseAge:
#   an upgrade is only auto-applied once its exact version has been VISIBLE to this
#   box for N days (default 4); so a compromised/regressed version has time to be
#   caught and yanked before we install it. Hyper-critical fixes bypass it.
#
# THE TRUST BOUNDARY (the load-bearing decision; read this):
#   apt's "trusted" bit means "signed by ANY key apt holds"; which is TRUE for every
#   added third-party repo (Docker CE, NodeSource, PPAs). It does NOT mean Canonical.
#   So we compute CANONICAL = trusted AND origin in an Ubuntu-origin allow-list AND
#   the fetch site matches an Ubuntu-host suffix. ONLY canonical packages take the
#   fast-path / count as real `-security`; anything else (incl. a signed third-party
#   that self-labels its suite `-security` or shadows a crown-jewel name) is GATED.
#
# THE POLICY (targeted, not blanket):
#   * Ubuntu `-security`/ESM-security (CANONICAL) are NOT touched here -
#     unattended-upgrades applies them fast, as today. (BLANKET=1 overrides.)
#   * Ubuntu `-updates` and THIRD-PARTY origins (Docker CE, PPAs, …); the real
#     supply-chain surface; are HELD (`apt-mark hold`, which u-u + manual apt both
#     skip) until their version ages past the grace, then applied.
#   * FAST-PATH (age 0): a crown-jewel package (openssh/libc6/openssl/kernel/…) from a
#     CANONICAL origin. A crown-jewel NAME from a NON-canonical origin is NOT
#     fast-pathed (that would be an age-0 hole straight through the gate); it is gated
#     for the LONGEST soak AND carded as an anomaly.
#   * DENY-LIST: an admin names a known-bad `pkg` or `pkg=version` and it is held
#     indefinitely + carded. (The kill switch is NOT that lever; it RELEASES holds.)
#   * FOREIGN holds: a package an admin dpkg-held that we did not is left alone.
#
# WHY HOLDS, NOT an unattended-upgrades config change: apt.conf list options
# CONCATENATE across drop-ins, so narrowing u-u's Allowed-Origins is unreliable. The
# hold is the real brake and u-u's stock default only auto-applies `-security`/ESM.
#
# ORDERING vs unattended-upgrades: u-u skips every dpkg-held package ("marked to be held
# back"), so a hold that went STALE when apt-daily refreshed the lists (a -updates
# version that has now reached -security) must be released BEFORE u-u picks its set, or
# the fix waits a full extra day. The hourly
# timer alone does not guarantee that, so install.sh --with-applier also installs
# apt-daily-upgrade.nethersec.conf: a drop-in that runs THIS unit as an ExecStartPre of
# apt-daily-upgrade.service, on the exact lists u-u is about to use.
#
# FAIL-SAFE (stricter than the detector, because this one writes):
#   * Always exit 0 (a failing oneshot trips OnFailure = a false incident); but exit
#     0 is NEVER silent. A genuine FAILURE; the apply errored, the pre-apply
#     simulation failed, dpkg is broken, or a package is stuck past the hard ceiling -
#     PAGES (critical): patching has stopped. An advisory (untrusted crown jewel, a
#     failed hold, a stale cache, a churn/anomaly, services needing restart) stays a
#     quiet card. A SUCCESSFUL apply posts a quiet, non-paging "done" note.
#   * Unreadable is never "done": can't resolve origin/trust (no python3-apt) -> apply
#     NOTHING, hold NOTHING, signal; never guess "trusted".
#   * Every write is guarded: simulate the exact subset first and refuse if it would
#     REMOVE anything or pull in an unexpected (non-kernel) new install.
#   * apt's own runs (apt-daily's list refresh, u-u's install) are waited out first. A
#     simulation or apply that still overlaps one is retried next run instead of paging,
#     until COLLIDE_PAGE_RUNS runs in a row have collided; then it pages as before. A run
#     whose lists changed after it sorted the set never installs, the Nth one included.
#   * Holds are write-AHEAD (recorded before `apt-mark hold`, re-asserted every run so
#     a failed hold self-heals); only holds WE recorded are ever released; DISABLING
#     the tool RELEASES our holds (a dangling hold with no manager is the worst
#     silent-unpatched state).
#   * Kill switch first; ships DRY-RUN by default (only HOSTSEC_APPLY_DRYRUN=0 installs);
#     per-event + per-run card cap.
#
# READ-ONLY on the system EXCEPT: apt-mark hold/unhold, and `apt-get install
# --only-upgrade` of the aged-in/fast-path set.
set -u

TAB=$(printf '\t')

# ---------------------------------------------------------------------------
# Config (all HOSTSEC_APPLY_*; loaded from /etc/nethersec/apply.env by systemd)
# ---------------------------------------------------------------------------
ENABLED="${HOSTSEC_APPLY_ENABLED:-1}"
DRYRUN="${HOSTSEC_APPLY_DRYRUN-1}"                  # ships DRY; only exactly 0 installs (checked below)
BLANKET="${HOSTSEC_APPLY_BLANKET:-0}"              # 1 = also grace-gate Canonical -security (discouraged)
GRACE_DAYS="${HOSTSEC_APPLY_GRACE_DAYS:-4}"        # gated pockets: -updates + third-party
SECUPDATE_GRACE_DAYS="${HOSTSEC_APPLY_SECUPDATE_GRACE_DAYS:-0}"          # only if BLANKET=1
CRITICAL_GATED_GRACE_DAYS="${HOSTSEC_APPLY_CRITICAL_GATED_GRACE_DAYS:-1}"  # opted-in critical third-party
CEILING_DAYS="${HOSTSEC_APPLY_CEILING_DAYS:-10}"   # per-package episode age -> escalate a card
STALECACHE_HOURS="${HOSTSEC_APPLY_STALECACHE_HOURS:-48}"
RESURFACE_SECS="${HOSTSEC_APPLY_RESURFACE_SECS:-21600}"  # 6h per-event card throttle
CHURN_CARD_COUNT="${HOSTSEC_APPLY_CHURN_COUNT:-6}"  # distinct versions in one episode -> churn anomaly
MAX_POSTS="${HOSTSEC_APPLY_MAX_POSTS:-8}"          # per-run card cap
APT_BUSY_WAIT_SECS="${HOSTSEC_APPLY_APT_BUSY_WAIT_SECS:-600}"  # max wait for apt-daily / u-u to finish first
APT_BUSY_POLL_SECS="${HOSTSEC_APPLY_APT_BUSY_POLL_SECS:-5}"
COLLIDE_PAGE_RUNS="${HOSTSEC_APPLY_COLLIDE_PAGE_RUNS:-3}"     # the Nth apt collision in a row pages as before
AUTOREBOOT="${HOSTSEC_APPLY_AUTOREBOOT:-0}"        # leave reboot to the detector + a person (unused)
STATE_DIR="${HOSTSEC_APPLY_STATE_DIR:-/var/lib/nethersec}"
SOURCE="${HOSTSEC_SOURCE:-$( (hostname -s 2>/dev/null || echo box) | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' | cut -c 1-40)}"
GROUP="${HOSTSEC_GROUP:-}"
KILL_FILE="${HOSTSEC_KILL_FILE:-/etc/nethersec/disabled}"
APPLY_KILL_FILE="${HOSTSEC_APPLY_KILL_FILE:-/etc/nethersec/apply-disabled}"
DENYLIST_FILE="${HOSTSEC_APPLY_DENYLIST_FILE:-/etc/nethersec/apply-denylist}"

# Sanitize every numeric knob once (a non-numeric env value must not silently become
# 0 -> apply/escalate immediately, nor break an arithmetic test).
for _v in GRACE_DAYS SECUPDATE_GRACE_DAYS CRITICAL_GATED_GRACE_DAYS CEILING_DAYS \
          STALECACHE_HOURS RESURFACE_SECS CHURN_CARD_COUNT MAX_POSTS \
          APT_BUSY_WAIT_SECS APT_BUSY_POLL_SECS COLLIDE_PAGE_RUNS; do
  eval "_cur=\$$_v"
  case "$_cur" in ''|*[!0-9]*)
    case "$_v" in
      GRACE_DAYS) _d=4 ;; SECUPDATE_GRACE_DAYS) _d=0 ;; CRITICAL_GATED_GRACE_DAYS) _d=1 ;;
      CEILING_DAYS) _d=10 ;; STALECACHE_HOURS) _d=48 ;; RESURFACE_SECS) _d=21600 ;;
      CHURN_CARD_COUNT) _d=6 ;; MAX_POSTS) _d=8 ;;
      APT_BUSY_WAIT_SECS) _d=600 ;; APT_BUSY_POLL_SECS) _d=5 ;; COLLIDE_PAGE_RUNS) _d=3 ;;
    esac
    eval "$_v=\$_d" ;;
  esac
done
[ "$APT_BUSY_POLL_SECS" -gt 0 ] || APT_BUSY_POLL_SECS=5   # 0 would make the wait loop spin forever
# Untrusted crown-jewel soak: default to the ordinary grace (>= it), NOT the shorter
# opt-in critical grace; the most-suspicious class must not age in the fastest.
ANOM_GRACE_DAYS="${HOSTSEC_APPLY_ANOM_GRACE_DAYS:-$GRACE_DAYS}"
case "$ANOM_GRACE_DAYS" in ''|*[!0-9]*) ANOM_GRACE_DAYS="$GRACE_DAYS" ;; esac

# What counts as CANONICAL (Ubuntu, GPG-signed by Canonical). A package is canonical
# only if it is trusted (its Canonical signature verified; a mirror cannot forge that)
# AND its origin label is one of these AND the fetch site ends with one of the
# suffixes. The default trusts Ubuntu's own mirrors (archive, security, ports and the
# country mirrors, all under .ubuntu.com). A box that pulls Ubuntu from another mirror
# (a cloud provider's, say) adds that host with HOSTSEC_APPLY_TRUSTED_SITES; the
# signature still has to verify, so a mirror can delay content but not forge it.
# Third-party repos (Docker origin=Docker, PPAs origin=LP-PPA-*) are excluded by the
# origin allow-list regardless of site.
TRUSTED_ORIGINS="${HOSTSEC_APPLY_TRUSTED_ORIGINS:-Ubuntu UbuntuESM UbuntuESMApps}"
TRUSTED_SITE_SUFFIXES="${HOSTSEC_APPLY_TRUSTED_SITES:-.ubuntu.com}"

# Crown-jewel names (space-separated globs). Fast-tracked at age 0 ONLY from a
# CANONICAL origin. A superset is safe: a name that isn't installed is a no-op.
FASTPATH_PKGS="${HOSTSEC_APPLY_FASTPATH_PKGS:-openssh-server openssh-client libc6 libc-bin sudo openssl libssl3 libssl1.1 libgnutls30 libgcrypt20 libpam-modules libpam-modules-bin libpam0g polkitd policykit-1 pkexec dbus libdbus-1-3 systemd libsystemd0 udev curl libcurl3-gnutls libcurl4 wget xz-utils liblzma5 zlib1g libwebp7 libtiff6 libtiff5 libexpat1 libjpeg-turbo8 libpng16-16 linux-image-generic linux-image-* linux-headers-generic linux-headers-* linux-modules-* linux-generic libnss3 libgssapi-krb5-2 libkrb5-3}"
# Third-party (non-canonical) NAMES an admin opts into a SHORTER soak for, because
# they are high-velocity critical surfaces (container escapes, node CVEs). Empty by
# default; NOT fast-pathed (age-0 from a non-canonical origin is a hole).
CRITICAL_GATED_PKGS="${HOSTSEC_APPLY_CRITICAL_GATED_PKGS:-}"
# New installs the guarded apply may pull in WITHOUT soaking: a kernel meta bump
# (linux-image-virtual / -generic) newly installs the versioned binaries of the same
# kernel upload. Every entry here is an AGE-0 new-install exemption (matched by NAME
# only; it does not re-check the dragged-in package's origin), so the list stays as
# narrow as the evidence. On Ubuntu 26.04 a kernel meta upgrade newly installs exactly
# linux-image-<V>-generic + linux-modules-<V>-generic + linux-main-modules-zfs-<V>-generic
# (linux-modules-<V> Depends on the zfs split). Without linux-main-modules-* every run
# would refuse the WHOLE apply set ("un-aged packages") while a kernel meta was
# pending. linux-headers-* / linux-modules-extra-* cover a headers
# meta and older releases. Other versioned kernel families (linux-tools-*,
# linux-cloud-tools-*, linux-objects-nvidia-*, linux-lib-rust-*, linux-buildinfo-*) are
# deliberately NOT here: none has been seen pulled in by a kernel meta. A box whose metas
# do pull one sets HOSTSEC_APPLY_KERNEL_NEWINSTALL_GLOBS, which REPLACES this list
# (so include the defaults); empty/unset = the default.
KERNEL_NEWINSTALL_GLOBS="${HOSTSEC_APPLY_KERNEL_NEWINSTALL_GLOBS:-linux-image-* linux-headers-* linux-modules-* linux-modules-extra-* linux-main-modules-*}"

# --- test/override seams (defaults are the real thing; harness overrides these) ---
APT_GET="${HOSTSEC_APPLY_APT_GET:-apt-get}"
APT_MARK="${HOSTSEC_APPLY_APT_MARK:-apt-mark}"
DPKG="${HOSTSEC_APPLY_DPKG:-dpkg}"
SYSTEMCTL="${HOSTSEC_APPLY_SYSTEMCTL:-systemctl}"
NEEDRESTART_BIN="${HOSTSEC_APPLY_NEEDRESTART:-needrestart}"
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P 2>/dev/null || echo .)
INTROSPECT="${HOSTSEC_APPLY_INTROSPECT_CMD:-python3 -I $SELF_DIR/apt-introspect.py}"
REPORT="${HOSTSEC_APPLY_REPORT_SCRIPT:-${HOSTSEC_REPORT_SCRIPT:-$SELF_DIR/nethersec-report.sh}}"
APT_LISTS_DIR="${HOSTSEC_APPLY_LISTS_DIR:-/var/lib/apt/lists}"
# apt.systemd.daily touches this on every SUCCESSFUL `apt-get update` (even a 304-only
# run); the authoritative "apt-daily is refreshing" signal, unlike list-file mtimes.
UPDATE_SUCCESS_STAMP="${HOSTSEC_APPLY_UPDATE_STAMP:-/var/lib/apt/periodic/update-success-stamp}"

log() { echo "apply-aged: $*" >&2; }
now() { echo "${HOSTSEC_APPLY_NOW:-$(date +%s 2>/dev/null || echo 0)}"; }

# The switch that arms the writes fails safe: only the exact value 0 installs. Anything
# else (empty, "false", "no", a typo, a trailing comment) stays in dry-run and says so.
case "$DRYRUN" in
  0|1) : ;;
  *) log "HOSTSEC_APPLY_DRYRUN='$DRYRUN' is not 0 or 1; staying in dry-run (only 0 installs)"; DRYRUN=1 ;;
esac
# The master switch: only 1 runs the applier, anything else turns it off (and releases
# its holds, below), which fails toward patched.
case "$ENABLED" in
  0|1) : ;;
  *) log "HOSTSEC_APPLY_ENABLED='$ENABLED' is not 0 or 1; treating it as 0 (off)" ;;
esac
NOW=$(now)
POSTS=0

# State files
FS_FILE="$STATE_DIR/first-seen.apply.tsv"       # name ver arch first_seen   (SOAK clock, per version)
EP_FILE="$STATE_DIR/episode.apply.tsv"          # name episode_start nver lastver (CEILING clock, per name)
HOLDS_FILE="$STATE_DIR/holds.apply.tsv"         # name ver reason hold_since   (write-ahead)
GRACE_FILE="$STATE_DIR/release-age-grace.tsv"   # name until_epoch             (informational; the detector does NOT read it)
HEARTBEAT="$STATE_DIR/apply-heartbeat"          # epoch of last completed run  (detector dead-man's switch)
COLLIDE_FILE="$STATE_DIR/apply-apt-collisions"  # runs in a row that stood down on an apt collision
LOCK_DIR="$STATE_DIR/apply.lock"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
atomic_write() { aw_f="$1"; aw_t="$aw_f.tmp.$$"; cat > "$aw_t" 2>/dev/null && mv -f "$aw_t" "$aw_f" 2>/dev/null || rm -f "$aw_t"; }
slug() { printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9' '-' | sed 's/^-*//; s/-*$//'; }

glob_match() {  # NAME "pat1 pat2 ..." -> 0 if NAME matches any glob
  gm_n="$1"; shift
  # The unquoted $* is split into patterns on purpose, but it must NOT also be
  # pathname-expanded: with a file like ./linux-main-modules-x in the cwd,
  # 'linux-main-modules-*' would expand to that literal name and stop matching. So
  # noglob for the loop, restoring the caller's setting.
  case $- in *f*) gm_f=1 ;; *) gm_f=0; set -f ;; esac
  gm_rc=1
  for gm_p in $*; do
    case "$gm_n" in $gm_p) gm_rc=0; break ;; esac  # intentional glob
  done
  [ "$gm_f" = 1 ] || set +f
  return $gm_rc
}

# is_canonical ORIGIN SITE TRUSTED -> 0 if this candidate is genuinely from Canonical.
is_canonical() {
  ic_o="$1"; ic_s="$2"; ic_t="$3"
  [ "$ic_t" = "1" ] || return 1
  # An origin label is one token. One carrying a space ("Ubuntu UbuntuESM") would
  # otherwise substring-match the space-joined allow-list below.
  case "$ic_o" in ''|*" "*) return 1 ;; esac
  case " $TRUSTED_ORIGINS " in *" $ic_o "*) : ;; *) return 1 ;; esac
  for ic_suf in $TRUSTED_SITE_SUFFIXES; do
    case "$ic_s" in *"$ic_suf") return 0 ;; esac
  done
  return 1
}

# signal EVENT SEVERITY TITLE DETAIL; a throttled card (emit on first raise / severity
# change / after RESURFACE), capped per run. The event name is cut to the protocol's 64
# characters (a long package name in apply-stuck-<name> could pass it). The state file
# is ev.apply-<event>, and every event already starts with apply-, so on disk it is
# ev.apply-apply-<rest> (the detector's own ev.apply-backstop never has that prefix).
# The throttle stamp is written only after a 2xx: a card that was not delivered, or
# was over the cap, goes again on the next run.
signal() {
  sg_ev=$(printf '%s' "$1" | cut -c 1-64); sg_sev="$2"; sg_title="$3"; sg_detail="$4"
  [ "$POSTS" -ge "$MAX_POSTS" ] && { log "post cap hit; suppressed: $sg_ev"; return 0; }
  sg_f="$STATE_DIR/ev.apply-$(slug "$sg_ev")"
  sg_psev=""; sg_pat=0
  if [ -f "$sg_f" ]; then
    read -r sg_psev sg_pat < "$sg_f" 2>/dev/null || { sg_psev=""; sg_pat=0; }
    case "$sg_pat" in ''|*[!0-9]*) sg_pat=0 ;; esac
    if [ "$sg_psev" = "$sg_sev" ] && [ $((NOW - sg_pat)) -lt "$RESURFACE_SECS" ]; then
      return 0
    fi
  fi
  POSTS=$((POSTS + 1))
  sg_ok=0
  if [ -x "$REPORT" ] || [ -f "$REPORT" ]; then
    if [ -n "$GROUP" ]; then
      sh "$REPORT" --kind security --source "$SOURCE" --group "$GROUP" --event "$sg_ev" \
        --state triggered --severity "$sg_sev" --title "$sg_title" --detail "$sg_detail" >/dev/null 2>&1 && sg_ok=1
    else
      sh "$REPORT" --kind security --source "$SOURCE" --event "$sg_ev" \
        --state triggered --severity "$sg_sev" --title "$sg_title" --detail "$sg_detail" >/dev/null 2>&1 && sg_ok=1
    fi
  fi
  if [ "$sg_ok" = 1 ]; then
    printf '%s %s\n' "$sg_sev" "$NOW" > "$sg_f" 2>/dev/null || :
  else
    log "post failed: $sg_ev (sent again on the next run)"
  fi
}

# --- exact-match state lookups (awk string compare, NOT grep; names/versions
# contain '.' which is a regex metachar) ---
held_by_us() { awk -F"$TAB" -v n="$1" '$1==n{f=1} END{exit !f}' "$HOLDS_FILE" 2>/dev/null; }
fs_lookup()  { awk -F"$TAB" -v n="$1" -v v="$2" -v a="$3" '$1==n&&$2==v&&$3==a{print; exit}' "$FS_FILE" 2>/dev/null; }
ep_lookup()  { awk -F"$TAB" -v n="$1" '$1==n{print; exit}' "$EP_FILE" 2>/dev/null; }

# --- hold state (write-AHEAD, self-healing) ---
record_hold() {  # name ver reason; record intent + sync BEFORE apt-mark hold; the
                 # apt-mark hold is re-asserted EVERY run (idempotent) so a hold that
                 # failed once self-heals, and a failure is carded, not just logged.
  rh_n="$1"; rh_v="$2"; rh_r="$3"
  if ! held_by_us "$rh_n"; then
    printf '%s\t%s\t%s\t%s\n' "$rh_n" "$rh_v" "$rh_r" "$NOW" >> "$HOLDS_FILE" 2>/dev/null || :
    sync 2>/dev/null || :
  fi
  if ! "$APT_MARK" hold "$rh_n" >/dev/null 2>&1; then
    signal "apply-hold-failed-$(slug "$rh_n")" warning "could not hold $rh_n" \
      "apt-mark hold $rh_n failed; the release-age soak is NOT enforced for it (u-u/manual apt could apply the un-soaked version). Check dpkg/apt state."
  fi
}
# unhold_ok NAME -> 0 when NAME is no longer held: `apt-mark unhold` worked, or showhold
# no longer lists it. An unhold fails while another apt, cloud-init or a config tool holds
# the dpkg lock. A failed one must keep its row: a hold nobody tracks is the worst
# silent-unpatched state (the next run would read it as an admin's pin and never touch it).
unhold_ok() {
  "$APT_MARK" unhold "$1" >/dev/null 2>&1 && return 0
  uo_held=$("$APT_MARK" showhold 2>/dev/null) || return 1
  printf '%s\n' "$uo_held" | grep -qxF "$1" && return 1
  return 0
}
unhold_failed() {  # name; the row stays, so the next run tries again
  log "unhold failed: $1 (kept on the list, tried again next run)"
  signal "apply-unhold-failed-$(slug "$1")" warning "could not release the hold on $1" \
    "apt-mark unhold $1 failed, so $1 stays held and no update installs for it, security fixes included. The applier keeps it on its list and tries again every run. Check that nothing else holds apt's lock, or run: sudo apt-mark unhold $1"
}
release_hold() {  # name; unhold + drop from state (only if WE recorded it, and only once it is released)
  rl_n="$1"; held_by_us "$rl_n" || return 0
  if ! unhold_ok "$rl_n"; then unhold_failed "$rl_n"; return 0; fi
  awk -F"$TAB" -v n="$rl_n" '$1!=n' "$HOLDS_FILE" 2>/dev/null > "$HOLDS_FILE.tmp.$$" \
    && mv -f "$HOLDS_FILE.tmp.$$" "$HOLDS_FILE" 2>/dev/null || rm -f "$HOLDS_FILE.tmp.$$"
}
release_all_holds() {  # disable/kill; fail toward patched, never frozen holds
  [ -f "$HOLDS_FILE" ] || return 0
  rah_keep="$HOLDS_FILE.keep.$$"
  : > "$rah_keep" 2>/dev/null || return 0
  while IFS= read -r rah_line; do
    rah_n=${rah_line%%"$TAB"*}
    [ -n "$rah_n" ] || continue
    unhold_ok "$rah_n" && continue
    unhold_failed "$rah_n"
    printf '%s\n' "$rah_line" >> "$rah_keep"
  done < "$HOLDS_FILE"
  # Only the holds that could not be released stay listed. If the swap fails, the whole
  # old list stays and every name is tried again (unholding a released one is harmless).
  mv -f "$rah_keep" "$HOLDS_FILE" 2>/dev/null || rm -f "$rah_keep"
}

# --- apt's own runs (see "let apt's own runs finish first" below) ---
# apt_busy -> 0 while apt-daily.service (`apt-get update`, then its download step) or
# u-u's install run is in progress, naming it in APT_BUSY_WHY. apt-daily-upgrade.service
# sitting in start-pre is waiting on THIS unit (the u-u drop-in), so that is not busy.
apt_busy() {
  case "$("$SYSTEMCTL" show -p ActiveState --value apt-daily.service 2>/dev/null)" in
    activating|deactivating|reloading) APT_BUSY_WHY="apt-daily.service running"; return 0 ;;
  esac
  case "$("$SYSTEMCTL" show -p SubState --value apt-daily-upgrade.service 2>/dev/null)" in
    start|start-post) APT_BUSY_WHY="unattended-upgrades running"; return 0 ;;
  esac
  return 1
}
# lists_fp -> the lists directory's own mtime. apt-get update changes it whenever it swaps
# a changed list in, and list files' own mtimes can't show that (apt sets them to the
# server's Last-Modified).
lists_fp() { stat -c '%y' "$APT_LISTS_DIR" 2>/dev/null || echo none; }
# apt_collision WHAT -> 0 when a failed or unsafe step looks like a collision with apt's
# own run (apt busy now, or the lists changed since this run started) and fewer than
# COLLIDE_PAGE_RUNS runs in a row have collided: logged, no card, the caller stands down
# and the next run retries on settled lists. Otherwise 1 and the caller carries on as
# before, so a real failure that only looks like a collision still pages within a few runs.
# APT_COLLIDED is 1 whenever it saw a collision (also the Nth one, which returns 1), and
# the streak length is in ac_n.
APT_COLLIDED=0
apt_collision() {
  APT_COLLIDED=0
  if apt_busy; then :
  elif [ "$(lists_fp)" != "$LISTS_FP0" ]; then APT_BUSY_WHY="apt lists changed during this run"
  else return 1; fi
  APT_COLLIDED=1
  ac_n=$(cat "$COLLIDE_FILE" 2>/dev/null || echo 0)
  case "$ac_n" in ''|*[!0-9]*) ac_n=0 ;; esac
  ac_n=$((ac_n + 1))
  printf '%s\n' "$ac_n" > "$COLLIDE_FILE" 2>/dev/null || :
  [ "$ac_n" -lt "$COLLIDE_PAGE_RUNS" ] || return 1
  log "$1 ($APT_BUSY_WHY): apt collision $ac_n in a row, no card, retrying next run"
  return 0
}
collisions_clear() { rm -f "$COLLIDE_FILE" 2>/dev/null || :; }
# apt_errors OUTPUT -> apt's E: lines (else its last line), joined and capped, for the card
# and the journal, so a page always says why apt refused.
apt_errors() {
  printf '%s\n' "$1" | awk '/^E: /{e = e (e == "" ? "" : " | ") $0} NF{last = $0} END{print (e != "" ? e : last)}' | cut -c1-400
}

# ---------------------------------------------------------------------------
# kill switch; FIRST. Disable RELEASES our holds AND removes the heartbeat/grace
# state (so the detector's dead-man's switch stays quiet for a deliberate pause). To
# stop a SPECIFIC bad version, use the deny-list instead.
# ---------------------------------------------------------------------------
if [ "${HOSTSEC_APPLY_KILL:-0}" = "1" ] || [ "$ENABLED" != "1" ] \
   || [ -f "$KILL_FILE" ] || [ -f "$APPLY_KILL_FILE" ]; then
  log "disabled (kill switch / ENABLED=0); releasing our holds and exiting 0"
  if mkdir -p "$STATE_DIR" 2>/dev/null; then
    [ -f "$HOLDS_FILE" ] && release_all_holds
    rm -f "$HEARTBEAT" "$GRACE_FILE" 2>/dev/null || :
  fi
  exit 0
fi

mkdir -p "$STATE_DIR" 2>/dev/null || { log "cannot mkdir $STATE_DIR; exit 0"; exit 0; }
[ -f "$HOLDS_FILE" ] || : > "$HOLDS_FILE" 2>/dev/null || :

# portable mkdir instance lock (no flock dependency; works under dash + the harness)
if ! mkdir "$LOCK_DIR" 2>/dev/null; then log "another run holds the lock; exit 0"; exit 0; fi
INTROFILE="$STATE_DIR/.intro.$$"; DHOLDS="$STATE_DIR/.dholds.$$"; GTMP="$STATE_DIR/.grace.$$"
SRCMEM="$STATE_DIR/.srcmem.$$"; FPSRC="$STATE_DIR/.fpsrc.$$"
cleanup() { rmdir "$LOCK_DIR" 2>/dev/null || :; rm -f "$INTROFILE" "$DHOLDS" "$GTMP" "$SRCMEM" "$FPSRC" "$DHOLDS.t.$$" "$GTMP.t.$$" 2>/dev/null || :; }
trap cleanup EXIT INT TERM
finish() { printf '%s\n' "$NOW" > "$HEARTBEAT" 2>/dev/null || :; exit 0; }

# ---------------------------------------------------------------------------
# let apt's own runs finish first. `apt-get -s` takes no lock, and `apt-get update`
# commits a changed list by deleting the old file and then renaming the new one in, so a
# simulation that reads the lists in that gap fails rc=100 ("E: Could not open file
# /var/lib/apt/lists/..._Packages"). When this timer and apt-daily's fire in the same
# second (systemd lines up timers due within the same minute) and a list changes, the
# simulation would page for a run that applied nothing. u-u's install
# run holds dpkg the same way: a live apply fails on its lock, and dpkg --audit sees its
# half-configured packages. So wait for both (bounded). If apt is still busy, stand down;
# a run that overlaps anyway is caught where it fails (apt_collision) and retried next run.
# ---------------------------------------------------------------------------
bw=0
while [ "$bw" -lt "$APT_BUSY_WAIT_SECS" ] && apt_busy; do
  [ "$bw" -eq 0 ] && log "waiting up to ${APT_BUSY_WAIT_SECS}s: $APT_BUSY_WHY"
  sleep "$APT_BUSY_POLL_SECS"; bw=$((bw + APT_BUSY_POLL_SECS))
done
LISTS_FP0=$(lists_fp)
apt_collision "apt still busy after ${APT_BUSY_WAIT_SECS}s, applied nothing" && finish

# ---------------------------------------------------------------------------
# preconditions; a WRITER must never proceed on a broken/unknowable base state.
# ---------------------------------------------------------------------------
dpkg_audit=$("$DPKG" --audit 2>/dev/null | grep -c . 2>/dev/null || echo 0)
case "$dpkg_audit" in ''|*[!0-9]*) dpkg_audit=0 ;; esac
if [ "$dpkg_audit" -gt 0 ]; then
  signal "apply-dpkg-broken" critical "dpkg in a broken state; applier standing down" \
    "dpkg --audit reports $dpkg_audit issue(s). Applied nothing. Run 'dpkg --configure -a' by hand."
  finish
fi

newest=0
for f in "$APT_LISTS_DIR"/*Packages "$APT_LISTS_DIR"/*_Release "$APT_LISTS_DIR"/*InRelease; do
  [ -f "$f" ] || continue
  m=$(date -r "$f" +%s 2>/dev/null || echo 0)
  case "$m" in ''|*[!0-9]*) m=0 ;; esac
  [ "$m" -gt "$newest" ] && newest="$m"
done
if [ "$newest" -gt 0 ]; then
  age_h=$(( (NOW - newest) / 3600 ))
  if [ "$age_h" -ge "$STALECACHE_HOURS" ]; then
    # A stale newest-list mtime alone is NOT "apt-daily is broken". apt only rewrites a
    # list file when the repo's CONTENT changes; an unchanged index returns 304 Not
    # Modified and the cached file is kept with its mtime untouched. So during a quiet
    # publishing window (weekends especially) every pocket can legitimately sit >48h old
    # while apt-daily refreshes fine every day. Corroborate with apt's own success stamp
    # (apt.systemd.daily touches it after every SUCCESSFUL update, 304s included): only
    # when that is ALSO stale (or absent/unreadable) is apt-daily genuinely frozen, so we
    # card + stand down. A fresh stamp means the metadata is valid-but-unchanged; don't
    # card, and PROCEED, because standing down here would silently stop applying aged-in
    # updates for the whole lull, and the existing metadata is a correct base to act on.
    upd_h=""
    if [ -f "$UPDATE_SUCCESS_STAMP" ]; then
      us=$(date -r "$UPDATE_SUCCESS_STAMP" +%s 2>/dev/null || echo 0)
      case "$us" in ''|*[!0-9]*) us=0 ;; esac
      [ "$us" -gt 0 ] && upd_h=$(( (NOW - us) / 3600 ))
    fi
    if [ -z "$upd_h" ] || [ "$upd_h" -ge "$STALECACHE_HOURS" ]; then
      usdesc="${upd_h}h"; [ -z "$upd_h" ] && usdesc="absent"
      signal "apply-stale-cache" warning "apt cache stale; release-age clock frozen" \
        "apt lists ${age_h}h old (>= ${STALECACHE_HOURS}h) and apt-daily's last successful update is ${usdesc} old. apt-daily may be broken. Applied nothing."
      finish
    fi
    log "apt lists ${age_h}h old but apt-daily updated ${upd_h}h ago (metadata unchanged, not stale); proceeding"
  fi
fi

# ---------------------------------------------------------------------------
# enumerate upgradable (authoritative origin + trust, HOLD-INDEPENDENT).
# Fail CLOSED: if introspection fails we cannot classify -> apply/hold nothing.
# (Existing holds stay in place; a transient failure must not release them; a
# PERSISTENT one is caught by the detector's stuck-hold backstop at the ceiling.)
# ---------------------------------------------------------------------------
if ! $INTROSPECT > "$INTROFILE" 2>/dev/null; then
  signal "apply-introspect-unavailable" warning "cannot resolve apt origins; applier idle" \
    "apt introspection failed (python3-apt missing or cache unreadable). Applied nothing (fail-closed); existing holds remain and are backstopped at the ceiling."
  finish
fi

# snapshot the real dpkg holds ONCE, to distinguish admin (foreign) holds from ours
DPKG_HOLDS=$("$APT_MARK" showhold 2>/dev/null || echo "")
is_dpkg_held() { printf '%s\n' "$DPKG_HOLDS" | grep -qxF "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
# classify each upgradable package. Loop runs in THIS shell (redirect, not a pipe),
# so state persists + cards emit inline.
# ---------------------------------------------------------------------------
deny_match() {  # name ver
  dm_n="$1"; dm_v="$2"
  [ -f "$DENYLIST_FILE" ] || return 1
  while IFS= read -r dl; do
    dl=$(printf '%s' "$dl" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$dl" ] || continue
    case "$dl" in
      *=*) [ "$dl" = "$dm_n=$dm_v" ] && return 0 ;;
      *)   [ "$dl" = "$dm_n" ] && return 0 ;;
    esac
  done < "$DENYLIST_FILE"
  return 1
}

NEWFS="$FS_FILE.tmp.$$"; : > "$NEWFS"
NEWEP="$EP_FILE.tmp.$$"; : > "$NEWEP"
: > "$DHOLDS"; : > "$GTMP"; : > "$SRCMEM"; : > "$FPSRC"
APPLY_SET=""

while IFS="$TAB" read -r name ver arch origin site archive trusted issec source; do
  [ -n "$name" ] || continue
  : "${trusted:=0}"; : "${issec:=0}"
  [ -n "$source" ] || source="$name"   # introspect fallback / pre-source-column skew
  canon=0   # reset per-iteration; only the classify 'else' branch recomputes it

  # --- soak clock (per exact version) ---
  fline=$(fs_lookup "$name" "$ver" "$arch")
  if [ -n "$fline" ]; then fseen=$(printf '%s' "$fline" | cut -f4); else fseen="$NOW"; fi
  case "$fseen" in ''|*[!0-9]*) fseen="$NOW" ;; esac
  printf '%s\t%s\t%s\t%s\n' "$name" "$ver" "$arch" "$fseen" >> "$NEWFS"

  # --- episode clock (per name; counts distinct versions this episode) ---
  epline=$(ep_lookup "$name")
  if [ -n "$epline" ]; then
    epstart=$(printf '%s' "$epline" | cut -f2); epnv=$(printf '%s' "$epline" | cut -f3); eplastv=$(printf '%s' "$epline" | cut -f4)
  else
    epstart="$NOW"; epnv=0; eplastv=""
  fi
  case "$epstart" in ''|*[!0-9]*) epstart="$NOW" ;; esac
  case "$epnv" in ''|*[!0-9]*) epnv=0 ;; esac
  [ "$ver" != "$eplastv" ] && epnv=$((epnv + 1))
  printf '%s\t%s\t%s\t%s\n' "$name" "$epstart" "$epnv" "$ver" >> "$NEWEP"

  soak_age=$((NOW - fseen)); [ "$soak_age" -lt 0 ] && soak_age=0
  epi_age=$((NOW - epstart)); [ "$epi_age" -lt 0 ] && epi_age=0

  # --- classify ---
  if is_dpkg_held "$name" && ! held_by_us "$name"; then
    class="foreign"; gd=0                              # an admin pin; never touch
  elif deny_match "$name" "$ver"; then
    class="deny"; gd=0
  else
    if is_canonical "$origin" "$site" "$trusted"; then canon=1; else canon=0; fi
    sec_real=0; [ "$canon" = 1 ] && [ "$issec" = "1" ] && sec_real=1
    if held_by_us "$name" && [ "$sec_real" = 1 ]; then
      class="fastpath"; gd=0                           # held pkg now has a real Canonical -security fix
    elif [ "$sec_real" = 1 ] && [ "$BLANKET" != "1" ]; then
      class="uu"; gd=0                                 # real Ubuntu -security: u-u's job, ignore
    elif glob_match "$name" "$FASTPATH_PKGS"; then
      if [ "$canon" = 1 ]; then class="fastpath"; gd=0
      else class="anom-critical"; gd="$ANOM_GRACE_DAYS"; fi   # crown-jewel NAME from a non-canonical origin
    elif [ "$sec_real" = 1 ] && [ "$BLANKET" = "1" ]; then
      class="gated"; gd="$SECUPDATE_GRACE_DAYS"        # blanket: soak -security too (discouraged)
    elif glob_match "$name" "$CRITICAL_GATED_PKGS"; then
      class="gated"; gd="$CRITICAL_GATED_GRACE_DAYS"
    else
      class="gated"; gd="$GRACE_DAYS"
    fi
  fi
  case "$gd" in ''|*[!0-9]*) gd="$GRACE_DAYS" ;; esac

  # lockstep grouping: record canonical members per (source, VERSION), and which
  # (source, version) pairs carry a canonical fast-path member (a crown-jewel). Post-loop,
  # held canonical siblings of THAT SAME upload are co-applied so `--only-upgrade` of the
  # subset isn't impossible. Keying on the version (not the source name alone) is what
  # pins it to one atomic upload: a source's binaries all share one binary version, which
  # is exactly what their `(= ${binary:Version})` interlock requires; so a differently
  # versioned package that merely shares the source name is a DIFFERENT upload and must
  # keep soaking, never ride in at age 0 on an unrelated crown-jewel version.
  if [ "$canon" = 1 ]; then
    printf '%s\t%s\t%s\t%s\n' "$source" "$ver" "$name" "$class" >> "$SRCMEM"
    [ "$class" = "fastpath" ] && printf '%s\t%s\n' "$source" "$ver" >> "$FPSRC"
  fi

  [ "$class" = "anom-critical" ] && signal "apply-anom-$(slug "$name")" warning \
    "Crown-jewel package from a NON-CANONICAL origin: $name" \
    "$name=$ver offered by origin='$origin' site='$site' (signed=$trusted, not Canonical). NOT fast-pathed; gated for the full soak + flagged. Verify this repo is legitimate."
  [ "$class" = "deny" ] && signal "apply-deny-$(slug "$name")" warning \
    "Deny-listed package held: $name" "$name=$ver is on the deny-list; held indefinitely, not applied."

  # --- decide apply vs hold ---
  case "$class" in
    uu|foreign) : ;;                                   # ignore
    fastpath)   APPLY_SET="$APPLY_SET $name" ;;
    deny)       printf '%s\t%s\t%s\n' "$name" "$ver" "deny-listed" >> "$DHOLDS" ;;
    gated|anom-critical)
      if [ "$soak_age" -ge $((gd * 86400)) ]; then
        APPLY_SET="$APPLY_SET $name"
      else
        printf '%s\t%s\t%s\n' "$name" "$ver" "$class(${gd}d)" >> "$DHOLDS"
        printf '%s\t%s\n' "$name" "$((fseen + gd * 86400))" >> "$GTMP"
      fi ;;
  esac

  # --- ceiling: pending past the hard ceiling but still not applied -> escalate ---
  case "$class" in fastpath|uu|deny|foreign) : ;; *)
    if [ "$epi_age" -ge $((CEILING_DAYS * 86400)) ]; then
      case " $APPLY_SET " in *" $name "*) : ;; *)
        signal "apply-stuck-$(slug "$name")" critical "Update stuck past the ${CEILING_DAYS}d ceiling: $name" \
          "$name ($class) pending $((epi_age / 86400))d (>= ${CEILING_DAYS}d) but not applied; held dep, version churn, or a rejected upgrade. Investigate." ;;
      esac
    fi ;;
  esac
  # --- churn: too many versions in one episode without aging in ---
  if [ "$epnv" -ge "$CHURN_CARD_COUNT" ] && [ "$class" != "foreign" ]; then
    signal "apply-churn-$(slug "$name")" warning "Abnormal version churn: $name" \
      "$name has published >= ${CHURN_CARD_COUNT} versions within one release-age episode without aging in; possible flooding to deny it ever soaking. Investigate the origin."
  fi
done < "$INTROFILE"

# ---------------------------------------------------------------------------
# lockstep fast-path promotion. A source package's binaries (e.g. krb5 -> libkrb5-3 +
# libgssapi-krb5-2 + libk5crypto3 + libkrb5support0, all at one version) ship as ONE
# atomic canonical upload with strict `(= ${binary:Version})` interdeps. When only the
# crown-jewel members are fast-pathed and the rest are gated/held, `apt-get --only-upgrade`
# of the subset is impossible ("held broken packages") -> a false apply-sim-failed page
# every run. So for any (source, version) upload that has a canonical fast-path member,
# co-apply its CANONICAL gated siblings OF THAT SAME VERSION (move them held -> apply).
# The version match is load-bearing: it pins promotion to the one upload the crown-jewel
# is from, so a differently versioned package sharing only the source NAME keeps soaking
# (no age-0 soak bypass on an unrelated version). Only canonical + gated members are pulled
# (never deny / anom / foreign, never a non-canonical shadow that self-claims the source),
# so this opens no age-0 hole the co-landing crown-jewel didn't already accept for that
# exact upload. Aged-in gated siblings never need this: same soak clock => age in together.
if [ -s "$FPSRC" ] && [ -s "$SRCMEM" ]; then
  FPSRCU=$(sort -u "$FPSRC")
  while IFS="$TAB" read -r sm_src sm_ver sm_name sm_class; do
    [ "$sm_class" = "gated" ] || continue
    printf '%s\n' "$FPSRCU" | grep -qxF "$sm_src$TAB$sm_ver" || continue
    case " $APPLY_SET " in *" $sm_name "*) : ;; *) APPLY_SET="$APPLY_SET $sm_name" ;; esac
    awk -F"$TAB" -v n="$sm_name" '$1!=n' "$DHOLDS" > "$DHOLDS.t.$$" 2>/dev/null && mv -f "$DHOLDS.t.$$" "$DHOLDS" 2>/dev/null || rm -f "$DHOLDS.t.$$"
    awk -F"$TAB" -v n="$sm_name" '$1!=n' "$GTMP"   > "$GTMP.t.$$"   2>/dev/null && mv -f "$GTMP.t.$$"   "$GTMP"   2>/dev/null || rm -f "$GTMP.t.$$"
    log "lockstep: co-applying held sibling $sm_name=$sm_ver (source '$sm_src') with its fast-pathed crown-jewel"
  done < "$SRCMEM"
fi

# commit the refreshed clocks (rows not seen this run are pruned; only seen rows written)
mv -f "$NEWFS" "$FS_FILE" 2>/dev/null || rm -f "$NEWFS"
mv -f "$NEWEP" "$EP_FILE" 2>/dev/null || rm -f "$NEWEP"
sort -u "$GTMP" 2>/dev/null | atomic_write "$GRACE_FILE"

# ---------------------------------------------------------------------------
# reconcile holds: set desired (write-ahead, re-asserted), release the rest we hold
# ---------------------------------------------------------------------------
DESIRED_NAMES=" "
if [ -s "$DHOLDS" ]; then
  while IFS="$TAB" read -r hn hv hr; do
    [ -n "$hn" ] || continue
    record_hold "$hn" "$hv" "$hr"
    DESIRED_NAMES="$DESIRED_NAMES$hn "
  done < "$DHOLDS"
fi
if [ -s "$HOLDS_FILE" ]; then
  cut -f1 "$HOLDS_FILE" 2>/dev/null | sort -u | while IFS= read -r existing; do
    [ -n "$existing" ] || continue
    case "$DESIRED_NAMES" in *" $existing "*) : ;; *) release_hold "$existing" ;; esac
  done
fi

# ---------------------------------------------------------------------------
# apply the aged-in + fast-path set; guarded: simulate, refuse removals / unexpected
# new installs (kernel new-installs are expected and whitelisted).
# ---------------------------------------------------------------------------
APPLY_SET=$(printf '%s\n' $APPLY_SET | awk 'NF' | sort -u | tr '\n' ' ' | sed 's/^ *//; s/ *$//')
[ -n "$APPLY_SET" ] || { log "nothing to apply this run"; collisions_clear; finish; }

# a fast-path package we currently hold must be unheld before we can upgrade it
for an in $APPLY_SET; do held_by_us "$an" && release_hold "$an"; done

SIM=$(LC_ALL=C "$APT_GET" -s install --only-upgrade $APPLY_SET 2>&1)
sim_rc=$?
if [ "$sim_rc" -ne 0 ]; then
  sim_err=$(apt_errors "$SIM")
  log "simulation failed rc=$sim_rc: ${sim_err:-no output}"
  apt_collision "simulation failed rc=$sim_rc, applied nothing" && finish
  signal "apply-sim-failed" critical "upgrade simulation failed; applied nothing" \
    "apt-get -s install --only-upgrade returned rc=$sim_rc${sim_err:+ ($sim_err)}. Held state unchanged. Set: $APPLY_SET"
  finish
fi
removes=$(printf '%s\n' "$SIM" | awk '/^Remv /{print $2}' | tr '\n' ' ' | sed 's/ *$//')
if [ -n "$removes" ]; then
  signal "apply-would-remove" warning "upgrade would REMOVE packages; refused" \
    "Aged-in set would remove: $removes. Applied nothing (never auto-remove). Set: $APPLY_SET"
  finish
fi
# A NEW install (an Inst line whose token after the package name is NOT '[oldver]')
# that is not on the kernel new-install allow-list = a not-yet-soaked dependency
# dragged in -> refuse (the whole set: the guarded write is all-or-nothing).
badnew=""
for ni in $(printf '%s\n' "$SIM" | awk '/^Inst /{ if ($3 !~ /^\[/) print $2 }'); do
  glob_match "$ni" "$KERNEL_NEWINSTALL_GLOBS" && continue
  badnew="$badnew $ni"
done
badnew=$(printf '%s' "$badnew" | sed 's/^ *//; s/ *$//')
if [ -n "$badnew" ]; then
  signal "apply-unexpected-newinstall" warning "upgrade would pull in un-aged packages; refused" \
    "Aged-in set would newly install: $badnew (not on the kernel new-install list, HOSTSEC_APPLY_KERNEL_NEWINSTALL_GLOBS); a not-yet-soaked dependency. Applied nothing. Set: $APPLY_SET"
  finish
fi

if [ "$DRYRUN" != "0" ]; then
  log "DRYRUN: would apply: $APPLY_SET (simulation clean: no removals, no unexpected new installs)"
  # A live apply ENDS these packages' episodes (next run they are no longer upgradable,
  # so their rows are pruned). Dry-run applies nothing, so without this the episode clock
  # keeps running from the first sighting: the package's NEXT release lands on a days-old
  # episode and pages "stuck past the ceiling" once CEILING_DAYS pass; a false page for
  # every high-velocity third-party package (docker-buildx-plugin, docker-ce, containerd.io)
  # on every box still in dry-run. Model the clean apply by ending the episodes here.
  awk -F"$TAB" -v s=" $APPLY_SET " 'index(s, " " $1 " ") == 0' "$EP_FILE" 2>/dev/null > "$EP_FILE.tmp.$$" \
    && mv -f "$EP_FILE.tmp.$$" "$EP_FILE" 2>/dev/null || rm -f "$EP_FILE.tmp.$$"
  collisions_clear
  finish
fi

# `install --only-upgrade` installs whatever the candidate is NOW. If apt-get update swapped
# the lists in since this run classified the set, that can be a version that never soaked,
# so a run whose lists moved (or that apt is busy with) never installs. Within the streak
# it stands down quietly; the Nth run in a row pages, and still installs nothing.
apt_collision "apt lists moved after classifying, applied nothing" && finish
if [ "$APT_COLLIDED" = 1 ]; then
  log "apt lists moved after classifying ($APT_BUSY_WHY): apt collision $ac_n in a row, applied nothing"
  signal "apply-apt-collisions" critical "applier keeps colliding with apt; applied nothing" \
    "$ac_n runs in a row stood down on apt's own runs, this one because: $APT_BUSY_WHY. Nothing was installed: the lists changed after the set was sorted, so the new candidates have not soaked. Check apt-daily and unattended-upgrades. Set: $APPLY_SET"
  finish
fi

# ---- the one guarded write ----
APPLY_OUT=$(DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l LC_ALL=C \
  "$APT_GET" -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    install --only-upgrade $APPLY_SET 2>&1)
apply_rc=$?
if [ "$apply_rc" -ne 0 ]; then
  apply_err=$(apt_errors "$APPLY_OUT")
  log "apply failed rc=$apply_rc: ${apply_err:-no output}"
  # A collision fails before dpkg runs (apt's lock, or a list mid-swap). If dpkg did run
  # and broke, the next run's dpkg --audit pages; if it did not, the next run applies.
  apt_collision "apply failed rc=$apply_rc" && finish
  signal "apply-failed" critical "package apply FAILED" \
    "apt-get install --only-upgrade rc=$apply_rc${apply_err:+ ($apply_err)} for: $APPLY_SET. Check 'journalctl -u nethersec-apply-aged'."
  finish
fi
collisions_clear
log "applied: $APPLY_SET"

# QUIET "done" note (non-paging, NOT a tracked card): an `info` report is a note in the
# hub's status channel with no card, so it never pages and never lingers as an open
# alert. Sent DIRECTLY (not via signal())
# so it is never throttled and never counts against MAX_POSTS; that budget must
# stay free for the apply-needrestart advisory just below.
if [ -x "$REPORT" ] || [ -f "$REPORT" ]; then
  ad_detail="release-age update(s) applied on ${SOURCE}: $APPLY_SET"
  if [ -n "$GROUP" ]; then
    sh "$REPORT" --kind security --source "$SOURCE" --group "$GROUP" --event apply-applied \
      --state triggered --severity info --title "Updates applied" --detail "$ad_detail" >/dev/null 2>&1 || log "done-note post failed"
  else
    sh "$REPORT" --kind security --source "$SOURCE" --event apply-applied \
      --state triggered --severity info --title "Updates applied" --detail "$ad_detail" >/dev/null 2>&1 || log "done-note post failed"
  fi
fi

# libs upgraded but long-lived services still map the OLD code = still vulnerable
# until restarted. The detector only watches KERNEL reboot-required, so surface it here.
if command -v "$NEEDRESTART_BIN" >/dev/null 2>&1; then
  nr=$("$NEEDRESTART_BIN" -b 2>/dev/null | awk -F= '/NEEDRESTART-SVC/{print $2}' | tr '\n' ' ' | sed 's/ *$//')
  if [ -n "$nr" ]; then
    signal "apply-needrestart" warning "services need restart after a library upgrade" \
      "Upgraded libs left services on old code: $nr. 'applied' != 'protected' until these restart or the box reboots."
  fi
fi

finish
