#!/usr/bin/env sh
# nethersec-status.sh: a read-only summary of the nethersec host scripts on this box:
# each part's timer and its last run, and the current state of every check.
#
#   sudo sh /opt/nethersec/nethersec-status.sh          # for a person
#   sudo sh /opt/nethersec/nethersec-status.sh --json   # one JSON object, for scripts and agents
#
# It reads /etc/nethersec, /var/lib/nethersec and `systemctl show`, and changes
# nothing. Without root it cannot read the mode-600 files in /etc/nethersec, and says
# "unknown" for what is in them. It never prints the report key or the report URL (a
# webhook URL is itself a secret), only whether they are set.
#
# A check reads "raised" while the detector holds it open (it posted `triggered` and has
# not posted `resolved` since), and "ok" otherwise. "ok" is only as fresh as the last
# run: a check that could not read is never "ok" by itself, it is listed under
# "unreadable" (and raises monitor-unreadable) instead.
#
# The --json shape (version 1). Times are Unix seconds; null means unknown or never.
#   {
#     "v": 1,
#     "installed": true,              /opt/nethersec exists
#     "version": "1a2b3c4d5e6f",      the commit install.sh copied, or "unknown"
#     "source": "web1",               HOSTSEC_SOURCE, or null
#     "transport": {"format": "hub", "url": "set", "key": "set"},
#                                     url and key: "set" | "missing" | "unknown"
#     "paused": {"all": false, "applier": false, "flood": false},   the kill switch files
#     "timers": [                     one per part whose unit is installed
#       {"part": "security-report", "timer_enabled": "enabled", "timer_active": "active",
#        "last_start": 1790000000, "last_result": "success", "last_done": 1790000005}
#     ],                              last_done: the script's own end-of-run stamp
#     "checks": [                     every check of the installed parts
#       {"part": "security-report", "event": "security-updates", "state": "raised",
#        "severity": "critical", "asserted_at": 1790000000}
#     ],                              asserted_at: when it was last posted (null when ok)
#     "unreadable": ["ssh-auth"],     what the last runs could not read
#     "detector": {"pending_security_updates": 3, "oldest_pending_since": 1789900000,
#                  "reboot_pending_since": null, "container_lists": 2},
#     "applier": {"installed": true, "enabled": true, "dry_run": true,
#                 "heartbeat": 1790000000, "holds": 1,
#                 "signals": [{"event": "apply-stale-cache", "severity": "warning", "posted_at": 1790000000}]},
#     "flood": {"installed": false, "mitigate": false}
#   }
#   applier.enabled / dry_run and flood.mitigate are null when the env file cannot be read.
#
# NETHERSEC_ROOT (a test seam, like install.sh's): a directory every system path above
# is placed under. NETHERSEC_NOW: the clock, for the "ago" times in the text output.
set -u
LC_ALL=C; export LC_ALL

JSON=0
case "${1:-}" in
  --json) JSON=1 ;;
  '') ;;
  -h|--help) sed -n '2,/^set -u/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "nethersec-status: unknown arg '$1' (use --json or nothing)" >&2; exit 2 ;;
esac

ROOT="${NETHERSEC_ROOT:-}"
PREFIX="$ROOT/opt/nethersec"
ETC="$ROOT/etc/nethersec"
STATE="$ROOT/var/lib/nethersec"
UNITS="$ROOT/etc/systemd/system"
NOW="${NETHERSEC_NOW:-$(date +%s 2>/dev/null || echo 0)}"
case "$NOW" in ''|*[!0-9]*) NOW=0 ;; esac
# Rows below are |-separated: a tab is IFS whitespace, so `read` would merge two
# tabs around an empty field and shift every field after it.
SEP='|'

SEC_EVENTS="security-updates reboot-security ssh-auth-burst log-error-rate apply-backstop script-path-writable thirdparty-updates docker-live-restore livepatch-off ipv4-options-drop-off ssh-password-auth unexpected-listener monitor-unreadable"
FLOOD_EVENTS="conn-flood net-flood http-flood smtp-flood monitor-unreadable-flood"

# --- small readers (each prints nothing when it cannot tell) ----------------------
num() { case "$1" in ''|*[!0-9]*) return 1 ;; *) printf '%s' "$1" ;; esac; }
first_word() { [ -r "$1" ] && awk 'NR == 1 { print $1; exit }' "$1" 2>/dev/null; }
# env_state FILE KEY: "unreadable" when the file exists but cannot be read, else the
# last value of KEY with quotes stripped (empty when unset or no file).
env_state() {
  if [ -f "$1" ] && [ ! -r "$1" ]; then echo unreadable; return; fi
  [ -f "$1" ] || return 0
  grep -E "^[[:space:]]*$2=" "$1" 2>/dev/null | tail -n 1 \
    | sed -e 's/^[^=]*=//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"
}
# A time from `systemctl show`: @<unix> with --timestamp=unix, else a date for date -d.
to_epoch() {
  case "$1" in
    ''|n/a|0) return 0 ;;
    @*) num "${1#@}" ;;
    *) d=$(date -d "$1" +%s 2>/dev/null) && num "$d" ;;
  esac
}
# show UNIT PROP...: Key=Value lines (the unix timestamp form when systemctl has it).
show() {
  sh_u="$1"; shift
  sh_args=""
  for sh_p in "$@"; do sh_args="$sh_args -p $sh_p"; done
  # shellcheck disable=SC2086
  systemctl show --timestamp=unix $sh_args "$sh_u" 2>/dev/null || systemctl show $sh_args "$sh_u" 2>/dev/null
}
prop() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1; }
jstr() { if [ -n "$1" ]; then printf '"%s"' "$1"; else printf 'null'; fi; }
jnum() { if [ -n "$1" ]; then printf '%s' "$1"; else printf 'null'; fi; }
jbool() { case "$1" in 1|true) printf 'true' ;; 0|false) printf 'false' ;; *) printf 'null' ;; esac; }
ago() {
  [ -n "$1" ] && [ "$NOW" -gt 0 ] || { printf 'never'; return; }
  a=$((NOW - $1)); [ "$a" -lt 0 ] && a=0
  if [ "$a" -lt 120 ]; then printf '%ss ago' "$a"
  elif [ "$a" -lt 7200 ]; then printf '%smin ago' "$((a / 60))"
  elif [ "$a" -lt 172800 ]; then printf '%sh ago' "$((a / 3600))"
  else printf '%sd ago' "$((a / 86400))"; fi
}

# --- install and config ----------------------------------------------------------
INSTALLED=0; [ -d "$PREFIX" ] && INSTALLED=1
VERSION=""; [ -r "$PREFIX/VERSION" ] && VERSION=$(head -n 1 "$PREFIX/VERSION" | tr -cd 'A-Za-z0-9._-')

RENV="$ETC/report.env"
# A box that moved the detector's state (HOSTSEC_STATE_DIR in report.env) is read there.
SD=$(env_state "$RENV" HOSTSEC_STATE_DIR)
case "$SD" in /*) STATE="$ROOT$SD" ;; esac
SOURCE=$(env_state "$RENV" HOSTSEC_SOURCE)
URL=$(env_state "$RENV" NETHERSEC_REPORT_URL)
KEY=$(env_state "$RENV" NETHERSEC_REPORT_KEY)
FMT=$(env_state "$RENV" NETHERSEC_REPORT_FORMAT)
if [ "$URL" = unreadable ]; then
  T_URL=unknown; T_KEY=unknown; T_FMT=""; SOURCE=""
else
  if [ -n "$URL" ]; then T_URL=set; else T_URL=missing; fi
  if [ -n "$KEY" ]; then T_KEY=set; else T_KEY=missing; fi
  case "$FMT" in
    hub|discord|ntfy|json) T_FMT="$FMT" ;;
    '') T_FMT=hub
        case "$URL" in https://discord.com/api/webhooks/*|https://*.discord.com/api/webhooks/*|https://discordapp.com/api/webhooks/*|https://*.discordapp.com/api/webhooks/*) T_FMT=discord ;; esac ;;
    *) T_FMT="" ;;
  esac
  printf '%s' "$SOURCE" | grep -Eq '^[a-z0-9][a-z0-9-]{0,39}$' || SOURCE=""
fi
KEY=""; URL=""   # never kept past this point

P_ALL=0; [ -f "$ETC/disabled" ] && P_ALL=1
P_APPLY=0; [ -f "$ETC/apply-disabled" ] && P_APPLY=1
P_FLOOD=0; [ -f "$ETC/flood-disabled" ] && P_FLOOD=1

HAS_SEC=0; [ -f "$UNITS/nethersec-security-report.service" ] && HAS_SEC=1
HAS_APPLY=0; [ -f "$UNITS/nethersec-apply-aged.service" ] && HAS_APPLY=1
HAS_FLOOD=0; [ -f "$UNITS/nethersec-flood-report.service" ] && HAS_FLOOD=1

# The same reading as the scripts: the applier runs only on 1 (unset or empty means 1),
# installs only on exactly 0, and the flood blocking is armed only on exactly 1.
A_EN=$(env_state "$ETC/apply.env" HOSTSEC_APPLY_ENABLED)
A_DRY=$(env_state "$ETC/apply.env" HOSTSEC_APPLY_DRYRUN)
case "$A_EN" in unreadable) A_EN="" ;; ''|1) A_EN=1 ;; *) A_EN=0 ;; esac
case "$A_DRY" in unreadable) A_DRY="" ;; 0) A_DRY=0 ;; *) A_DRY=1 ;; esac
F_MIT=$(env_state "$ETC/flood.env" HOSTSEC_FLOOD_MITIGATE)
case "$F_MIT" in unreadable) F_MIT="" ;; 1) F_MIT=1 ;; *) F_MIT=0 ;; esac
if [ ! -f "$ETC/apply.env" ]; then A_EN=1; A_DRY=1; fi
if [ ! -f "$ETC/flood.env" ]; then F_MIT=0; fi

# --- timers ------------------------------------------------------------------------
TIMERS=""   # part|enabled|active|last_start|result|last_done
add_timer() {  # part has done_file
  [ "$2" = 1 ] || return 0
  at_t=$(show "nethersec-$1.timer" UnitFileState ActiveState)
  at_s=$(show "nethersec-$1.service" ExecMainStartTimestamp Result)
  at_en=$(prop "$at_t" UnitFileState | tr -cd 'a-z-')
  at_ac=$(prop "$at_t" ActiveState | tr -cd 'a-z-')
  at_ls=$(to_epoch "$(prop "$at_s" ExecMainStartTimestamp)")
  at_rs=$(prop "$at_s" Result | tr -cd 'a-z-')
  at_ld=$(num "$(first_word "$3")" || :)
  TIMERS="${TIMERS}$1$SEP$at_en$SEP$at_ac$SEP$at_ls$SEP$at_rs$SEP$at_ld
"
}
add_timer security-report "$HAS_SEC" "$STATE/lastrun"
add_timer apply-aged "$HAS_APPLY" "$STATE/apply-heartbeat"
add_timer flood-report "$HAS_FLOOD" "$STATE/flood-lastrun"

# --- checks ------------------------------------------------------------------------
CHECKS=""   # part|event|state|severity|asserted_at
add_checks() {  # part file_prefix events
  for ac_e in $3; do
    ac_f="$STATE/$2$ac_e"
    if [ -f "$ac_f" ]; then
      ac_sev=""; ac_at=""
      read -r ac_sev ac_at _rest < "$ac_f" 2>/dev/null || :
      case "$ac_sev" in critical|warning|info) ;; *) ac_sev="" ;; esac
      ac_at=$(num "$ac_at" || :)
      CHECKS="${CHECKS}$1$SEP$ac_e${SEP}raised$SEP$ac_sev$SEP$ac_at
"
    else
      CHECKS="${CHECKS}$1$SEP$ac_e${SEP}ok$SEP$SEP
"
    fi
  done
}
# A detector run by hand (no unit installed) still left its state: list its checks too.
[ "$HAS_SEC" = 1 ] || [ -f "$STATE/lastrun" ] && add_checks security-report "ev." "$SEC_EVENTS"
[ "$HAS_FLOOD" = 1 ] || [ -f "$STATE/flood-lastrun" ] && add_checks flood-report "flood-ev." "$FLOOD_EVENTS"

UNREAD=""
for uf in "$STATE/unreadable" "$STATE/flood-unreadable"; do
  [ -r "$uf" ] || continue
  UNREAD="$UNREAD $(head -n 1 "$uf" | tr -cd 'a-z0-9 ._-')"
done
UNREAD=$(printf '%s\n' $UNREAD | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ *$//')

# --- detector details ----------------------------------------------------------
PEND=""; PEND_OLD=""
FS="$STATE/first-seen.security-updates.tsv"
if [ -r "$FS" ]; then
  PEND=$(awk -F'\t' 'NF >= 4 && $4 == "0" && $2 ~ /^[0-9]+$/ { n++ } END { print n + 0 }' "$FS")
  PEND_OLD=$(awk -F'\t' 'NF >= 4 && $4 == "0" && $2 ~ /^[0-9]+$/ && (m == "" || $2 + 0 < m + 0) { m = $2 } END { print m }' "$FS")
elif [ "$HAS_SEC" = 1 ] && [ -d "$STATE" ]; then
  PEND=0
fi
RB_SINCE=$(num "$(first_word "$STATE/reboot-pending.since")" || :)
CTR=""
if [ -d "$STATE/ctrpkg" ]; then
  CTR=$(find "$STATE/ctrpkg" -maxdepth 1 -name '*.sent' -type f 2>/dev/null | wc -l | tr -d ' ')
elif [ "$HAS_SEC" = 1 ]; then CTR=0; fi

# --- applier details -------------------------------------------------------------
A_HB=$(num "$(first_word "$STATE/apply-heartbeat")" || :)
A_HOLDS=0
[ -r "$STATE/holds.apply.tsv" ] && A_HOLDS=$(awk -F'\t' 'NF && $1 != "" { n++ } END { print n + 0 }' "$STATE/holds.apply.tsv")
SIGNALS=""   # event|severity|posted_at
# The applier writes ev.apply-<event>, and each of its events starts with apply-, so its
# files are ev.apply-apply-*. That also leaves out the detector's own ev.apply-backstop.
for sf in "$STATE"/ev.apply-apply-*; do
  [ -f "$sf" ] || continue
  s_ev=$(basename "$sf" | sed 's/^ev\.apply-//' | tr -cd 'a-z0-9._-')
  s_sev=""; s_at=""
  read -r s_sev s_at _rest < "$sf" 2>/dev/null || :
  case "$s_sev" in critical|warning|info) ;; *) s_sev="" ;; esac
  s_at=$(num "$s_at" || :)
  SIGNALS="${SIGNALS}$s_ev$SEP$s_sev$SEP$s_at
"
done

# ================================================================================
if [ "$JSON" = 1 ]; then
  printf '{"v":1,"installed":%s,"version":%s,"source":%s,' "$(jbool "$INSTALLED")" "$(jstr "$VERSION")" "$(jstr "$SOURCE")"
  printf '"transport":{"format":%s,"url":"%s","key":"%s"},' "$(jstr "$T_FMT")" "$T_URL" "$T_KEY"
  printf '"paused":{"all":%s,"applier":%s,"flood":%s},' "$(jbool "$P_ALL")" "$(jbool "$P_APPLY")" "$(jbool "$P_FLOOD")"
  printf '"timers":['
  sep=""
  printf '%s' "$TIMERS" | while IFS="$SEP" read -r p en ac ls rs ld; do
    [ -n "$p" ] || continue
    printf '%s{"part":"%s","timer_enabled":%s,"timer_active":%s,"last_start":%s,"last_result":%s,"last_done":%s}' \
      "$sep" "$p" "$(jstr "$en")" "$(jstr "$ac")" "$(jnum "$ls")" "$(jstr "$rs")" "$(jnum "$ld")"
    sep=","
  done
  printf '],"checks":['
  sep=""
  printf '%s' "$CHECKS" | while IFS="$SEP" read -r p e st sv at; do
    [ -n "$p" ] || continue
    printf '%s{"part":"%s","event":"%s","state":"%s","severity":%s,"asserted_at":%s}' \
      "$sep" "$p" "$e" "$st" "$(jstr "$sv")" "$(jnum "$at")"
    sep=","
  done
  printf '],"unreadable":['
  sep=""
  for u in $UNREAD; do printf '%s"%s"' "$sep" "$u"; sep=","; done
  printf '],"detector":{"pending_security_updates":%s,"oldest_pending_since":%s,"reboot_pending_since":%s,"container_lists":%s},' \
    "$(jnum "$PEND")" "$(jnum "$PEND_OLD")" "$(jnum "$RB_SINCE")" "$(jnum "$CTR")"
  printf '"applier":{"installed":%s,"enabled":%s,"dry_run":%s,"heartbeat":%s,"holds":%s,"signals":[' \
    "$(jbool "$HAS_APPLY")" "$(jbool "$A_EN")" "$(jbool "$A_DRY")" "$(jnum "$A_HB")" "$A_HOLDS"
  sep=""
  printf '%s' "$SIGNALS" | while IFS="$SEP" read -r e sv at; do
    [ -n "$e" ] || continue
    printf '%s{"event":"%s","severity":%s,"posted_at":%s}' "$sep" "$e" "$(jstr "$sv")" "$(jnum "$at")"
    sep=","
  done
  printf ']},"flood":{"installed":%s,"mitigate":%s}}\n' "$(jbool "$HAS_FLOOD")" "$(jbool "$F_MIT")"
  exit 0
fi

# --- text --------------------------------------------------------------------------
yn() { case "$1" in 1) printf 'yes' ;; 0) printf 'no' ;; *) printf 'unknown' ;; esac; }
if [ "$INSTALLED" = 1 ]; then
  echo "nethersec ${VERSION:-unknown} in /opt/nethersec, source ${SOURCE:-unknown}"
else
  echo "nethersec is not installed here (no /opt/nethersec)."
fi
echo "transport: format ${T_FMT:-unknown}, url $T_URL, key $T_KEY"
[ "$P_ALL" = 1 ] && echo "PAUSED: /etc/nethersec/disabled exists, so no script runs."
[ "$P_APPLY" = 1 ] && echo "PAUSED: the applier (/etc/nethersec/apply-disabled exists)."
[ "$P_FLOOD" = 1 ] && echo "PAUSED: the flood detector (/etc/nethersec/flood-disabled exists)."
echo ""
printf '%s' "$TIMERS" | while IFS="$SEP" read -r p en ac ls rs ld; do
  [ -n "$p" ] || continue
  echo "$p: timer ${en:-?}/${ac:-?}, last started $(ago "$ls") (${rs:-?}), last finished $(ago "$ld")"
done
[ -n "$TIMERS" ] || echo "no nethersec timers are installed."
if [ -n "$CHECKS" ]; then
  echo ""
  raised=$(printf '%s' "$CHECKS" | awk -F'|' '$3 == "raised"')
  if [ -n "$raised" ]; then
    echo "raised:"
    printf '%s\n' "$raised" | while IFS="$SEP" read -r p e st sv at; do
      echo "  $e (${sv:-?}), last posted $(ago "$at")"
    done
  else
    echo "raised: none"
  fi
  echo "ok: $(printf '%s' "$CHECKS" | awk -F'|' '$3 == "ok" { printf "%s%s", s, $2; s = " " }')"
fi
[ -n "$UNREAD" ] && echo "could not read on the last run: $UNREAD"
if [ "$HAS_SEC" = 1 ]; then
  echo ""
  echo "pending security updates: ${PEND:-unknown}${PEND_OLD:+, oldest seen $(ago "$PEND_OLD")}"
  if [ -n "$RB_SINCE" ]; then echo "reboot pending since $(ago "$RB_SINCE")"; else echo "no reboot pending"; fi
  echo "container package lists sent: ${CTR:-0}"
fi
if [ "$HAS_APPLY" = 1 ]; then
  echo ""
  echo "applier: enabled $(yn "$A_EN"), dry-run $(yn "$A_DRY"), last run $(ago "$A_HB"), holds $A_HOLDS"
  printf '%s' "$SIGNALS" | while IFS="$SEP" read -r e sv at; do
    [ -n "$e" ] || continue
    echo "  last $e (${sv:-?}) posted $(ago "$at")"
  done
fi
if [ "$HAS_FLOOD" = 1 ]; then
  echo ""
  echo "flood detector: mitigation armed $(yn "$F_MIT")"
fi
exit 0
