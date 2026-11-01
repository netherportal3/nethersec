#!/usr/bin/env bash
# install.sh: install, update or remove the nethersec host scripts on this box.
#
# Run it as root from a clone of the repo. It copies the scripts into /opt/nethersec
# (root-owned, directories 755) and the systemd units run them from there, so the clone
# can live anywhere and be owned by anyone. Re-running it from a newer clone updates the
# scripts and the units of every part already installed.
#
#   sudo bash host/install.sh --source web1 --report-url https://hub.example.com/v1/report --new-key
#   sudo bash host/install.sh --with-applier --with-flood      # add parts later
#   sudo bash host/install.sh --uninstall                      # keeps /etc/nethersec
#
# Flags:
#   --source NAME      this box's source name: a-z, 0-9 and '-', 1 to 40 characters
#   --report-url URL   where reports go (for the hub: https://<hub>/v1/report). A URL
#                      that is itself a secret (a Discord webhook, a private ntfy topic)
#                      goes through --url-stdin instead, never on the command line
#   --url-stdin        read the report URL from stdin (the first line)
#   --format FMT       hub (default) | discord | ntfy | json
#   --new-key          make a new key on this box (32 random bytes), write it to
#                      /etc/nethersec/report.env (mode 600), and print only the line for
#                      the hub's keys file: `<source> <sha256 of the key> page`. Until the
#                      hub has that line, it refuses the box's reports and each run sends
#                      them again
#   --key-stdin        read the key from stdin instead (after the URL with --url-stdin)
#   --replace-key      allow --new-key or --key-stdin to replace a key report.env
#                      already has (without it they refuse, so a key the hub knows is
#                      never swapped out by accident)
#   --group LABEL      an optional grouping label sent with every report
#   --with-applier     also install the release-age applier (ships DRY-RUN). Installs
#                      python3-apt if missing, turns on Docker live-restore where Docker
#                      is installed, and adds a drop-in so unattended-upgrades runs the
#                      applier right before itself
#   --with-flood       also install the flood detector (mitigation ships OFF)
#   --run-now          run each installed part once after installing
#   --check-path       only check that nothing on the path to /opt/nethersec is
#                      world-writable, then exit (0 = clean). Writes nothing; no root needed
#   --uninstall        release the applier's package holds (through its kill switch),
#                      clear the flood detector's drops, remove the units and
#                      /opt/nethersec. Keeps /etc/nethersec and /var/lib/nethersec
#   --purge            with --uninstall: also take off the IP-options drop and the module
#                      block, and remove /etc/nethersec and /var/lib/nethersec
#
# A key is never taken on the command line (other local users can read a process's
# arguments), and an existing report.env is never replaced: only the values you pass
# change in it, and the installer says which.
#
# NETHERSEC_ROOT (a test seam): a directory every system path above is placed under.
# With it set, the root check is skipped. The harness host/test/install.test.sh uses it.
set -euo pipefail
umask 022

ROOT="${NETHERSEC_ROOT:-}"
PREFIX_REAL=/opt/nethersec
PREFIX="$ROOT$PREFIX_REAL"
ETC="$ROOT/etc/nethersec"
STATE="$ROOT/var/lib/nethersec"
UNITS="$ROOT/etc/systemd/system"
DROPIN_DIR="$UNITS/apt-daily-upgrade.service.d"
DROPIN="$DROPIN_DIR/nethersec-apply-aged.conf"
ENV_FILE="$ETC/report.env"

say()  { echo "==> $*"; }
warn() { echo "install: WARNING: $*" >&2; }
die()  { echo "install: $*" >&2; exit 1; }

SOURCE=""; URL=""; URL_STDIN=0; FORMAT=""; NEW_KEY=0; KEY_STDIN=0; REPLACE_KEY=0; GROUP=""
WITH_APPLIER=0; WITH_FLOOD=0; RUN_NOW=0; CHECK_PATH=0; UNINSTALL=0; PURGE=0
need_val() { [ $# -ge 2 ] || { echo "install: $1 needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    --source)       need_val "$@"; SOURCE="$2"; shift 2 ;;
    --report-url)   need_val "$@"; URL="$2"; shift 2 ;;
    --url-stdin)    URL_STDIN=1; shift ;;
    --format)       need_val "$@"; FORMAT="$2"; shift 2 ;;
    --new-key)      NEW_KEY=1; shift ;;
    --key-stdin)    KEY_STDIN=1; shift ;;
    --replace-key)  REPLACE_KEY=1; shift ;;
    --group)        need_val "$@"; GROUP="$2"; shift 2 ;;
    --with-applier) WITH_APPLIER=1; shift ;;
    --with-flood)   WITH_FLOOD=1; shift ;;
    --run-now)      RUN_NOW=1; shift ;;
    --check-path)   CHECK_PATH=1; shift ;;
    --uninstall)    UNINSTALL=1; shift ;;
    --purge)        PURGE=1; shift ;;
    -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install: unknown arg '$1' (see --help)" >&2; exit 2 ;;
  esac
done

SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

# --- the path check -----------------------------------------------------------
# The units run these scripts as root from /opt/nethersec. If any local user can write
# a directory on that path (one without the sticky bit) or a script in it, they can put
# their own script in its place before the next root run. Check 6 of security-report.sh
# flags the same thing later if a box drifts back.
path_problems() {
  pp_d="$PREFIX"
  while [ ! -e "$pp_d" ] && [ "$pp_d" != "/" ]; do pp_d=$(dirname -- "$pp_d"); done
  while :; do
    if [ -n "$(find "$pp_d" -maxdepth 0 -type d -perm -0002 ! -perm -1000 2>/dev/null)" ]; then
      printf '%s\n' "$pp_d"
    fi
    [ "$pp_d" = "/" ] && break
    pp_d=$(dirname -- "$pp_d")
  done
  for pp_f in "$PREFIX"/*.sh "$PREFIX"/*.py; do
    [ -f "$pp_f" ] || continue
    if [ -n "$(find "$pp_f" -maxdepth 0 -perm -0002 2>/dev/null)" ]; then printf '%s\n' "$pp_f"; fi
  done
}
refuse_bad_path() {
  rb=$(path_problems)
  [ -n "$rb" ] || return 0
  echo "install: refusing. Any local user can write these, and the units would run scripts from them as root:" >&2
  printf '%s\n' "$rb" | sed 's/^/  /' >&2
  echo "Fix, then re-run:  sudo chmod o-w $(printf '%s\n' "$rb" | tr '\n' ' ' | sed 's/ *$//')" >&2
  exit 1
}

if [ "$CHECK_PATH" = 1 ]; then
  refuse_bad_path
  say "path ok: nothing on the path to $PREFIX_REAL is world-writable."
  exit 0
fi

if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then die "run as root (sudo)"; fi

# --- report.env helpers ---------------------------------------------------------
# env_get KEY: the last value of KEY in report.env, quotes stripped (empty if unset).
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  grep -E "^[[:space:]]*$1=" "$ENV_FILE" 2>/dev/null | tail -n 1 \
    | sed -e 's/^[^=]*=//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/" || :
}
# set_kv KEY VALUE: set KEY=VALUE in report.env, dropping any earlier line for KEY (set
# or commented out). The value is written literally: no sed replacement, so any
# character round-trips. The temp file is made mode 600 before anything goes into it.
set_kv() {
  sk_tmp="$ENV_FILE.tmp.$$"
  install -m 0600 /dev/null "$sk_tmp"
  grep -Ev "^[[:space:]]*#?[[:space:]]*$1=" "$ENV_FILE" >> "$sk_tmp" 2>/dev/null || :
  printf '%s=%s\n' "$1" "$2" >> "$sk_tmp"
  cat "$sk_tmp" > "$ENV_FILE"
  rm -f "$sk_tmp"
}
is_discord_url() {
  case "$1" in
    https://discord.com/api/webhooks/*|https://*.discord.com/api/webhooks/*|https://discordapp.com/api/webhooks/*|https://*.discordapp.com/api/webhooks/*) return 0 ;;
  esac
  return 1
}
valid_source() { printf '%s' "$1" | grep -Eq '^[a-z0-9][a-z0-9-]{0,39}$'; }

# ================================================================================
# --uninstall
# ================================================================================
if [ "$UNINSTALL" = 1 ]; then
  # 1. The applier's holds come off FIRST: a hold with nobody left to release it is the
  #    worst silent-unpatched state. Its kill switch releases every hold it recorded.
  holds_f="$STATE/holds.apply.tsv"
  apply_state=$( { grep -E '^[[:space:]]*HOSTSEC_APPLY_STATE_DIR=' "$ETC/apply.env" 2>/dev/null || :; } | tail -n 1 | sed 's/^[^=]*=//')
  [ -n "$apply_state" ] && holds_f="$ROOT$apply_state/holds.apply.tsv"
  if [ -s "$holds_f" ]; then
    held=$(cut -f1 "$holds_f" | awk 'NF' | sort -u)
    [ -f "$PREFIX/apply-aged-upgrades.sh" ] || die "the applier holds packages ($holds_f) but $PREFIX_REAL/apply-aged-upgrades.sh is gone. Release them by hand: sudo apt-mark unhold $(printf '%s\n' "$held" | tr '\n' ' ')"
    install -d -m 0755 "$ETC"
    : > "$ETC/apply-disabled"
    say "releasing the applier's package holds (kill switch $ETC/apply-disabled)..."
    HOSTSEC_APPLY_KILL_FILE="$ETC/apply-disabled" HOSTSEC_KILL_FILE="$ETC/disabled" \
      HOSTSEC_APPLY_STATE_DIR="$(dirname -- "$holds_f")" sh "$PREFIX/apply-aged-upgrades.sh" || :
    still=$(apt-mark showhold 2>/dev/null | awk 'NF' | sort -u | comm -12 - <(printf '%s\n' "$held") || :)
    if [ -n "$still" ]; then
      die "these packages are still held, so nothing was removed: $(printf '%s\n' "$still" | tr '\n' ' ')
Release them (sudo apt-mark unhold <name>), then run --uninstall again."
    fi
    say "holds released: $(printf '%s\n' "$held" | tr '\n' ' ')"
  fi
  # 2. The flood detector's own nftables table (its self-expiring drops), if any.
  if [ -f "$PREFIX/flood-report.sh" ] && command -v nft >/dev/null 2>&1 \
     && nft list table inet nethersec_flood >/dev/null 2>&1; then
    sh "$PREFIX/flood-report.sh" --unmitigate || :
  fi
  # 3. Timers, units and the unattended-upgrades drop-in.
  for u in nethersec-security-report nethersec-apply-aged nethersec-flood-report; do
    if [ -f "$UNITS/$u.timer" ] || [ -f "$UNITS/$u.service" ]; then
      systemctl disable --now "$u.timer" >/dev/null 2>&1 || :
      rm -f "$UNITS/$u.timer" "$UNITS/$u.service"
      say "removed $u"
    fi
  done
  if [ -f "$DROPIN" ]; then
    rm -f "$DROPIN"; rmdir "$DROPIN_DIR" 2>/dev/null || :
    say "removed the unattended-upgrades drop-in"
  fi
  systemctl daemon-reload || :
  # 4. The mitigations installed by hand stay unless --purge: they protect the box on
  #    their own and need nothing from /opt/nethersec.
  ipopt_unit="$UNITS/nethersec-ipv4-options-drop.service"
  kmod_conf="$ROOT/etc/modprobe.d/nethersec-blocked-modules.conf"
  if [ "$PURGE" = 1 ]; then
    if [ -f "$ipopt_unit" ] && [ -f "$PREFIX/ipv4-options-drop.sh" ]; then
      HOSTSEC_ETC_DIR="$ETC" HOSTSEC_UNIT_DIR="$UNITS" bash "$PREFIX/ipv4-options-drop.sh" --remove || warn "the IP-options drop could not be removed"
    fi
    if [ -f "$kmod_conf" ] && [ -f "$PREFIX/kernel-modules-block.sh" ]; then
      HOSTSEC_MODPROBE_DIR="$ROOT/etc/modprobe.d" bash "$PREFIX/kernel-modules-block.sh" --remove || warn "the module block could not be removed"
    fi
  fi
  rm -rf "$PREFIX"
  say "removed $PREFIX_REAL"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$ETC" "$STATE"
    say "removed /etc/nethersec and /var/lib/nethersec"
  else
    say "kept /etc/nethersec (your settings and key) and /var/lib/nethersec. --uninstall --purge removes them."
    [ -f "$ipopt_unit" ] && say "the IP-options drop stays on. To take it off: sudo bash host/ipv4-options-drop.sh --remove (from the clone)"
    [ -f "$kmod_conf" ] && say "the module block stays on. To take it off: sudo bash host/kernel-modules-block.sh --remove (from the clone)"
  fi
  exit 0
fi

# ================================================================================
# install / update
# ================================================================================
for f in security-report.sh nethersec-report.sh cve-severity.py nethersec-security-report.service \
         nethersec-security-report.timer report.env.example; do
  [ -f "$SELF_DIR/$f" ] || die "$f not found next to install.sh. Run it from a clone of the repo."
done
[ "$PURGE" = 0 ] || die "--purge goes with --uninstall"
[ -z "$SOURCE" ] || valid_source "$SOURCE" || die "--source must be a-z, 0-9 and '-', 1 to 40 characters, starting with a letter or digit (got '$SOURCE')"
case "$FORMAT" in ''|hub|discord|ntfy|json) ;; *) die "--format must be hub, discord, ntfy or json (got '$FORMAT')" ;; esac
[ "$NEW_KEY" = 0 ] || [ "$KEY_STDIN" = 0 ] || die "use --new-key or --key-stdin, not both"
[ -z "$URL" ] || [ "$URL_STDIN" = 0 ] || die "use --report-url or --url-stdin, not both"
if [ -n "$URL" ] && is_discord_url "$URL"; then
  die "a Discord webhook URL is a secret: pass it on stdin with --url-stdin, not on the command line"
fi

# Everything read from stdin comes first: the URL line, then the key line.
NEW_KEY_VALUE=""
if [ "$URL_STDIN" = 1 ]; then
  IFS= read -r URL || [ -n "$URL" ] || die "--url-stdin: nothing on stdin"
  URL=$(printf '%s' "$URL" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  [ -n "$URL" ] || die "--url-stdin: the URL line is empty"
fi
if [ "$KEY_STDIN" = 1 ]; then
  IFS= read -r NEW_KEY_VALUE || [ -n "$NEW_KEY_VALUE" ] || die "--key-stdin: nothing on stdin"
  NEW_KEY_VALUE=$(printf '%s' "$NEW_KEY_VALUE" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  [ -n "$NEW_KEY_VALUE" ] || die "--key-stdin: the key line is empty"
fi
if [ -n "$URL" ]; then
  case "$URL" in http://*|https://*) ;; *) die "the report URL must start with http:// or https://" ;; esac
  printf '%s' "$URL" | grep -q '[[:space:]]' && die "the report URL has a space in it"
fi

# What report.env will say once this run is done, worked out before anything changes,
# so a refusal leaves the box exactly as it was.
EFF_SOURCE="${SOURCE:-$(env_get HOSTSEC_SOURCE)}"
EFF_URL="${URL:-$(env_get NETHERSEC_REPORT_URL)}"
EFF_FORMAT="${FORMAT:-$(env_get NETHERSEC_REPORT_FORMAT)}"
if [ -z "$EFF_FORMAT" ]; then
  if [ -n "$EFF_URL" ] && is_discord_url "$EFF_URL"; then EFF_FORMAT=discord; else EFF_FORMAT=hub; fi
fi
OLD_KEY=$(env_get NETHERSEC_REPORT_KEY)
if [ "$NEW_KEY" = 1 ] || [ "$KEY_STDIN" = 1 ]; then
  if [ -n "$OLD_KEY" ] && [ "$REPLACE_KEY" = 0 ]; then
    die "$ENV_FILE already has a key. The hub may know it, so it is left alone. To replace it, add --replace-key (then update the hub's keys file)."
  fi
fi
if [ "$NEW_KEY" = 1 ]; then
  [ "$EFF_FORMAT" = hub ] || die "--new-key makes a hub key; the $EFF_FORMAT format does not use one (use --key-stdin for an ntfy or json token)"
  [ -n "$EFF_SOURCE" ] || die "--new-key needs the box's source name: add --source NAME"
  valid_source "$EFF_SOURCE" || die "the source in $ENV_FILE ('$EFF_SOURCE') is not a valid source name; pass --source NAME"
  NEW_KEY_VALUE=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
  printf '%s' "$NEW_KEY_VALUE" | grep -Eq '^[0-9a-f]{64}$' || die "could not read 32 random bytes from /dev/urandom"
fi
if [ "$KEY_STDIN" = 1 ]; then
  if [ "$EFF_FORMAT" = hub ]; then
    printf '%s' "$NEW_KEY_VALUE" | grep -Eq '^[0-9a-f]{64}$' || die "a hub key is 64 lowercase hex characters (32 random bytes)"
  else
    printf '%s' "$NEW_KEY_VALUE" | grep -Eq '^[!-~]{1,512}$' || die "the key must be 1 to 512 printable characters with no spaces"
  fi
fi

refuse_bad_path

# --- 1. the scripts, into /opt/nethersec ----------------------------------------
# Staged next to the live copy and swapped in with two renames, so a timer that fires
# meanwhile runs either the old set or the new one, never a mix.
install -d -m 0755 "$(dirname -- "$PREFIX")"
STAGE="$PREFIX.new.$$"
rm -rf "$STAGE"
install -d -m 0755 "$STAGE"
for f in "$SELF_DIR"/*.sh; do install -m 0755 "$f" "$STAGE/"; done
for f in "$SELF_DIR"/*.py; do install -m 0644 "$f" "$STAGE/"; done
VERSION=$(git -c safe.directory="$(dirname -- "$SELF_DIR")" -C "$SELF_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
printf '%s\n' "$VERSION" | tr -cd 'A-Za-z0-9._\n-' > "$STAGE/VERSION"
chmod 0644 "$STAGE/VERSION"
if [ -d "$PREFIX" ]; then
  mv "$PREFIX" "$PREFIX.old.$$"
  mv "$STAGE" "$PREFIX"
  rm -rf "$PREFIX.old.$$"
  say "updated $PREFIX_REAL (version $VERSION)"
else
  mv "$STAGE" "$PREFIX"
  say "installed the scripts in $PREFIX_REAL (version $VERSION)"
fi
refuse_bad_path

# --- 2. /etc/nethersec/report.env -------------------------------------------------
install -d -m 0755 "$ETC"
if [ ! -f "$ENV_FILE" ]; then
  install -m 0600 "$SELF_DIR/report.env.example" "$ENV_FILE"
  say "wrote $ENV_FILE from the template"
fi
chmod 600 "$ENV_FILE"
# set_if_changed KEY VALUE LABEL: change one value and say so (never echoing a secret).
set_if_changed() {
  [ -n "$2" ] || return 0
  sc_old=$(env_get "$1")
  [ "$sc_old" = "$2" ] && return 0
  set_kv "$1" "$2"
  if [ -z "$sc_old" ]; then say "set $1 in $ENV_FILE${3:+ ($3)}"; else say "CHANGED $1 in $ENV_FILE${3:+ ($3)}"; fi
}
set_if_changed HOSTSEC_SOURCE "$SOURCE" "$SOURCE"
set_if_changed NETHERSEC_REPORT_URL "$URL" ""
set_if_changed NETHERSEC_REPORT_FORMAT "$FORMAT" "$FORMAT"
set_if_changed HOSTSEC_GROUP "$GROUP" "$GROUP"
if [ -n "$NEW_KEY_VALUE" ]; then
  set_kv NETHERSEC_REPORT_KEY "$NEW_KEY_VALUE"
  if [ -n "$OLD_KEY" ]; then say "REPLACED the key in $ENV_FILE"; else say "wrote the key to $ENV_FILE (mode 600)"; fi
fi

# --- 3. state dir and the detector's units -----------------------------------------
# The state says which fixes are not installed yet, so only root reads it.
install -d -m 0700 "$STATE"
install -d -m 0755 "$UNITS"
install -m 0644 "$SELF_DIR/nethersec-security-report.service" "$UNITS/nethersec-security-report.service"
install -m 0644 "$SELF_DIR/nethersec-security-report.timer" "$UNITS/nethersec-security-report.timer"

# --- 4. the applier (asked for now, or installed before) ---------------------------
if [ "$WITH_APPLIER" = 1 ] || [ -f "$UNITS/nethersec-apply-aged.service" ]; then
  # A live applier installs Docker and containerd upgrades once they age in. Without
  # live-restore that restarts every container on the box, so turn it on first. It is a
  # no-op where Docker is not installed.
  if [ "$WITH_APPLIER" = 1 ] && command -v docker >/dev/null 2>&1; then
    say "turning on Docker live-restore (keeps containers up through a Docker upgrade)..."
    bash "$PREFIX/docker-live-restore.sh" \
      || warn "Docker live-restore is not on. A Docker upgrade here would restart every container. See the output above."
  fi
  # python3-apt reads each package's origin and trust. The applier FAILS CLOSED (applies
  # and holds nothing) without it.
  if ! python3 -c 'import apt' >/dev/null 2>&1; then
    say "python3-apt is missing; installing it (the applier needs it to tell origins apart)..."
    { apt-get update && apt-get install -y python3-apt; } >/dev/null 2>&1 \
      || warn "could not install python3-apt. The applier will apply and hold nothing until it is present."
  fi
  if [ ! -f "$ETC/apply.env" ]; then
    install -m 0600 "$SELF_DIR/apply.env.example" "$ETC/apply.env"
    say "wrote $ETC/apply.env from the template. It ships DRY-RUN (HOSTSEC_APPLY_DRYRUN=1)."
  fi
  chmod 600 "$ETC/apply.env"
  install -m 0644 "$SELF_DIR/nethersec-apply-aged.service" "$UNITS/nethersec-apply-aged.service"
  install -m 0644 "$SELF_DIR/nethersec-apply-aged.timer" "$UNITS/nethersec-apply-aged.timer"
  # Run the applier right BEFORE unattended-upgrades, so a hold that went stale when
  # apt-daily refreshed the lists is released before u-u skips the package as held. A
  # drop-in for the stock unit, never an edit of it; the file's header says why it cannot
  # deadlock or block u-u.
  install -d -m 0755 "$DROPIN_DIR"
  install -m 0644 "$SELF_DIR/apt-daily-upgrade.nethersec.conf" "$DROPIN"
  say "unattended-upgrades now runs the applier first (drop-in $DROPIN)"
  [ -f "$ETC/apply-disabled" ] && warn "the applier is paused: $ETC/apply-disabled exists. Remove it to resume."
fi

# --- 5. the flood detector (asked for now, or installed before) --------------------
if [ "$WITH_FLOOD" = 1 ] || [ -f "$UNITS/nethersec-flood-report.service" ]; then
  command -v python3 >/dev/null 2>&1 || warn "python3 not found: the flood detector's HTTP check stays dark until it is installed."
  if [ ! -f "$ETC/flood.env" ]; then
    install -m 0600 "$SELF_DIR/flood.env.example" "$ETC/flood.env"
    say "wrote $ETC/flood.env from the template. Thresholds ship HIGH; mitigation ships OFF."
  fi
  chmod 600 "$ETC/flood.env"
  install -m 0644 "$SELF_DIR/nethersec-flood-report.service" "$UNITS/nethersec-flood-report.service"
  install -m 0644 "$SELF_DIR/nethersec-flood-report.timer" "$UNITS/nethersec-flood-report.timer"
fi

# --- 6. systemd -------------------------------------------------------------------
systemctl daemon-reload
for u in nethersec-security-report nethersec-apply-aged nethersec-flood-report; do
  [ -f "$UNITS/$u.timer" ] || continue
  systemctl enable --now "$u.timer" >/dev/null
  say "timer on: $u.timer"
done
if [ "$RUN_NOW" = 1 ]; then
  for u in nethersec-security-report nethersec-apply-aged nethersec-flood-report; do
    [ -f "$UNITS/$u.service" ] || continue
    say "running $u once..."
    systemctl start "$u.service" || :
    journalctl -u "$u.service" -n 20 --no-pager || :
  done
fi

# --- 7. what is still missing -----------------------------------------------------
EFF_KEY="${NEW_KEY_VALUE:-$OLD_KEY}"
[ -n "$EFF_URL" ] || warn "no report URL yet: re-run with --report-url URL (or --url-stdin). The scripts post nothing until then."
if [ "$EFF_FORMAT" = hub ] && [ -z "$EFF_KEY" ]; then
  warn "no key yet: re-run with --new-key (or --key-stdin). The hub format posts nothing without one."
fi
[ -n "$EFF_SOURCE" ] || warn "HOSTSEC_SOURCE is not set: the scripts fall back to the hostname. Re-run with --source NAME."
[ -f "$ETC/disabled" ] && warn "every nethersec script is paused: $ETC/disabled exists."

cat <<EOF

Done. On this box:
  Status:            sudo sh $PREFIX_REAL/nethersec-status.sh        (--json for scripts)
  Run once now:      sudo systemctl start nethersec-security-report.service
  Last run's log:    journalctl -u nethersec-security-report.service -n 30 --no-pager
  Pause everything:  sudo touch /etc/nethersec/disabled
  Uninstall:         sudo bash host/install.sh --uninstall   (from the clone)
EOF
if [ -f "$UNITS/nethersec-apply-aged.service" ]; then
  cat <<EOF
  Applier:           DRY-RUN until HOSTSEC_APPLY_DRYRUN=0 in /etc/nethersec/apply.env
                     journalctl -u nethersec-apply-aged.service -n 40 --no-pager
                     pause (releases its holds): sudo touch /etc/nethersec/apply-disabled
EOF
fi
if [ -f "$UNITS/nethersec-flood-report.service" ]; then
  cat <<EOF
  Flood detector:    mitigation OFF until HOSTSEC_FLOOD_MITIGATE=1 in /etc/nethersec/flood.env
                     clear its drops: sudo sh $PREFIX_REAL/flood-report.sh --unmitigate
EOF
fi
if [ "$NEW_KEY" = 1 ]; then
  KEY_HASH=$(printf '%s' "$NEW_KEY_VALUE" | sha256sum | cut -d' ' -f1)
  cat <<EOF

Until the hub has the line below, it refuses this box's reports, and each run sends them
again: nothing is lost. Add it to the hub's keys file (keys.txt; it holds the key's hash,
not the key), then send them now with
  sudo systemctl start nethersec-security-report.service
or wait for the next run.
$EFF_SOURCE $KEY_HASH page
EOF
fi
exit 0
