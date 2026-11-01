#!/usr/bin/env sh
# nethersec-status.test.sh: offline harness for the read-only status summary. Builds a
# fake box under NETHERSEC_ROOT (install dir, env files, units, state files) and puts a
# mock `systemctl` on PATH, then checks the --json shape and values, the text output,
# and that the key and the URL are never printed.
#
#   sh host/test/nethersec-status.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../nethersec-status.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "nethersec-status.test: python3 is required"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/nst.$$"); mkdir -p "$WORK"
BIN="$WORK/bin"; mkdir -p "$BIN"
R="$WORK/root"
NOW=1790000000
TAB=$(printf '\t')
KEY=$(printf 'cd%.0s' $(seq 1 32))
URL="https://discord.com/api/webhooks/123456789012345678/$(printf 'y%.0s' 1 2 3 4 5 6)"

# systemctl show: Key=Value lines from $MOCK_SC/<unit>, only the asked-for properties.
# MOCK_SC_OLD=1 acts like an old systemctl that has no --timestamp option.
cat > "$BIN/systemctl" <<'EOF'
#!/bin/sh
[ "$1" = show ] || exit 1
shift
props=""; unit=""
while [ $# -gt 0 ]; do
  case "$1" in
    --timestamp=*) [ "${MOCK_SC_OLD:-0}" = 1 ] && { echo "unknown option $1" >&2; exit 1; }; shift ;;
    -p) props="$props $2"; shift 2 ;;
    *) unit="$1"; shift ;;
  esac
done
for p in $props; do
  v=$(sed -n "s/^$p=//p" "$MOCK_SC/$unit" 2>/dev/null | head -n 1)
  echo "$p=$v"
done
EOF
chmod +x "$BIN/systemctl"

PASS=0; FAIL=0; CUR=""
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; }

box() {  # a box with the detector and the applier installed
  rm -rf "$R"; mkdir -p "$R/opt/nethersec" "$R/etc/nethersec" "$R/etc/systemd/system" "$R/var/lib/nethersec" "$WORK/sc"
  echo "1a2b3c4d5e6f" > "$R/opt/nethersec/VERSION"
  { echo "HOSTSEC_SOURCE=web1"; echo "NETHERSEC_REPORT_URL=https://hub.example.com/v1/report"; echo "NETHERSEC_REPORT_KEY=$KEY"; } > "$R/etc/nethersec/report.env"
  echo "HOSTSEC_APPLY_DRYRUN=1" > "$R/etc/nethersec/apply.env"
  for u in nethersec-security-report nethersec-apply-aged; do
    : > "$R/etc/systemd/system/$u.service"; : > "$R/etc/systemd/system/$u.timer"
    printf 'UnitFileState=enabled\nActiveState=active\n' > "$WORK/sc/$u.timer"
    printf 'ExecMainStartTimestamp=@%s\nResult=success\n' "$((NOW - 600))" > "$WORK/sc/$u.service"
  done
  S="$R/var/lib/nethersec"
  echo "$((NOW - 590))" > "$S/lastrun"
  echo "$((NOW - 3000))" > "$S/apply-heartbeat"
  echo "critical $((NOW - 7200))" > "$S/ev.security-updates"
  echo "warning $((NOW - 100)) tcp/0.0.0.0:8080" > "$S/ev.unexpected-listener"
  echo "ssh-auth log-errors" > "$S/unreadable"
  printf 'curl\t%s\t8.5.0-2ubuntu10.5\t0\thigh\tCVE-2026-1\t-\nsudo\t%s\t1.9.15\t0\t-\t-\t-\nold\t%s\t1.0\t%s\t-\t-\t-\n' \
    "$((NOW - 200000))" "$((NOW - 1000))" "$((NOW - 9000))" "$((NOW - 50))" > "$S/first-seen.security-updates.tsv"
  echo "$((NOW - 86400))" > "$S/reboot-pending.since"
  mkdir -p "$S/ctrpkg"; : > "$S/ctrpkg/web.sent"; : > "$S/ctrpkg/db.sent"
  printf 'libfoo\t1.0\tgated\t%s\n' "$((NOW - 99))" > "$S/holds.apply.tsv"
  # The names the applier really writes: ev.apply-<event>, and its events start with
  # apply-. ev.apply-backstop is the detector's own check, not an applier signal.
  echo "warning $((NOW - 400))" > "$S/ev.apply-apply-stale-cache"
  echo "critical $((NOW - 300))" > "$S/ev.apply-backstop"
}
runit() {
  OUT=$(env PATH="$BIN:$PATH" MOCK_SC="$WORK/sc" MOCK_SC_OLD="${OLD:-0}" NETHERSEC_ROOT="$R" NETHERSEC_NOW="$NOW" sh "$SCRIPT" "$@" 2>&1)
  RC=$?
}
# j EXPR: a Python expression over the parsed --json output `s`.
j() {
  printf '%s' "$OUT" > "$WORK/out.json"
  python3 -I - "$WORK/out.json" "$1" <<'PY' && ok || bad "json check failed: $1 (got: $OUT)"
import json, sys
s = json.load(open(sys.argv[1], encoding="ascii"))
sys.exit(0 if eval(sys.argv[2], {"s": s, "NOW": 1790000000}) else 1)
PY
}
a_has()   { printf '%s' "$OUT" | grep -qF -- "$1" && ok || bad "expected output to contain '$1' (got: $OUT)"; }
a_lacks() { printf '%s' "$OUT" | grep -qF -- "$1" && bad "output must NOT contain '$1'" || ok; }
check() {  # the state of one check in the JSON
  printf 'next(c for c in s["checks"] if c["event"] == "%s")' "$1"
}

# 1. the JSON shape and values on a box with the detector and the applier.
t "json-full"
box; runit --json
[ "$RC" = 0 ] && ok || bad "exit $RC"
j 's["v"] == 1 and s["installed"] is True and s["version"] == "1a2b3c4d5e6f" and s["source"] == "web1"'
j 's["transport"] == {"format": "hub", "url": "set", "key": "set"}'
j 's["paused"] == {"all": False, "applier": False, "flood": False}'
j '[t["part"] for t in s["timers"]] == ["security-report", "apply-aged"]'
j 's["timers"][0] == {"part": "security-report", "timer_enabled": "enabled", "timer_active": "active", "last_start": NOW - 600, "last_result": "success", "last_done": NOW - 590}'
j 's["timers"][1]["last_done"] == NOW - 3000'
j "$(check security-updates) == {\"part\": \"security-report\", \"event\": \"security-updates\", \"state\": \"raised\", \"severity\": \"critical\", \"asserted_at\": NOW - 7200}"
j "$(check unexpected-listener)[\"state\"] == \"raised\""
j "$(check ssh-auth-burst) == {\"part\": \"security-report\", \"event\": \"ssh-auth-burst\", \"state\": \"ok\", \"severity\": None, \"asserted_at\": None}"
j 'len(s["checks"]) == 13 and not any(c["part"] == "flood-report" for c in s["checks"])'
j 's["unreadable"] == ["ssh-auth", "log-errors"]'
j 's["detector"] == {"pending_security_updates": 2, "oldest_pending_since": NOW - 200000, "reboot_pending_since": NOW - 86400, "container_lists": 2}'
j 's["applier"] == {"installed": True, "enabled": True, "dry_run": True, "heartbeat": NOW - 3000, "holds": 1, "signals": [{"event": "apply-stale-cache", "severity": "warning", "posted_at": NOW - 400}]}'
j "$(check apply-backstop) == {\"part\": \"security-report\", \"event\": \"apply-backstop\", \"state\": \"raised\", \"severity\": \"critical\", \"asserted_at\": NOW - 300}"
j 's["flood"] == {"installed": False, "mitigate": False}'
a_lacks "$KEY"; a_lacks "hub.example.com"

# 2. the text output says the same, still without the key or the URL.
t "text"
box; runit
[ "$RC" = 0 ] && ok || bad "exit $RC"
a_has "nethersec 1a2b3c4d5e6f in /opt/nethersec, source web1"
a_has "transport: format hub, url set, key set"
a_has "security-report: timer enabled/active, last started 10min ago (success)"
a_has "security-updates (critical), last posted 2h ago"
a_has "could not read on the last run: ssh-auth log-errors"
a_has "pending security updates: 2"; a_has "reboot pending since 24h ago"
a_has "applier: enabled yes, dry-run yes"; a_has "holds 1"
a_has "last apply-stale-cache (warning) posted 6min ago"; a_lacks "apply-apply-"; a_lacks "last apply-backstop"
a_lacks "$KEY"; a_lacks "hub.example.com"

# 3. the flood detector: its own checks and state files, and the armed flag.
t "flood"
box; : > "$R/etc/systemd/system/nethersec-flood-report.service"
printf 'UnitFileState=enabled\nActiveState=active\n' > "$WORK/sc/nethersec-flood-report.timer"
echo "HOSTSEC_FLOOD_MITIGATE=1" > "$R/etc/nethersec/flood.env"
echo "warning $((NOW - 60))" > "$R/var/lib/nethersec/flood-ev.http-flood"
echo "$((NOW - 30))" > "$R/var/lib/nethersec/flood-lastrun"
echo "http-flood" > "$R/var/lib/nethersec/flood-unreadable"
runit --json
j 's["flood"] == {"installed": True, "mitigate": True}'
j "$(check http-flood) == {\"part\": \"flood-report\", \"event\": \"http-flood\", \"state\": \"raised\", \"severity\": \"warning\", \"asserted_at\": NOW - 60}"
j 's["timers"][2]["part"] == "flood-report" and s["timers"][2]["last_done"] == NOW - 30'
j 's["unreadable"] == ["ssh-auth", "log-errors", "http-flood"]'

# 4. kill switches, a live applier, and the Discord format picked from the URL.
t "paused-live-discord"
box; : > "$R/etc/nethersec/disabled"; : > "$R/etc/nethersec/apply-disabled"
echo "HOSTSEC_APPLY_DRYRUN=0" > "$R/etc/nethersec/apply.env"
{ echo "HOSTSEC_SOURCE=web1"; echo "NETHERSEC_REPORT_URL=$URL"; } > "$R/etc/nethersec/report.env"
runit --json
j 's["paused"] == {"all": True, "applier": True, "flood": False}'
j 's["applier"]["dry_run"] is False'
j 's["transport"] == {"format": "discord", "url": "set", "key": "missing"}'
a_lacks "webhooks"
runit; a_has "PAUSED: /etc/nethersec/disabled exists"; a_lacks "webhooks"

# 4b. the switches read the way the scripts read them: the applier installs only on an
#     exact 0, runs only on 1 (unset or empty is 1), and the flood blocking is armed only
#     on an exact 1. "true", "yes" and a value with a comment after it are none of those.
t "switches-read-like-the-scripts"
for v in true yes "0 # live"; do
  box; : > "$R/etc/systemd/system/nethersec-flood-report.service"
  printf 'HOSTSEC_APPLY_ENABLED=%s\nHOSTSEC_APPLY_DRYRUN=%s\n' "$v" "$v" > "$R/etc/nethersec/apply.env"
  printf 'HOSTSEC_FLOOD_MITIGATE=%s\n' "$v" > "$R/etc/nethersec/flood.env"
  runit --json
  j 's["applier"]["enabled"] is False and s["applier"]["dry_run"] is True and s["flood"]["mitigate"] is False'
done
box; printf 'HOSTSEC_APPLY_ENABLED=\nHOSTSEC_APPLY_DRYRUN=\n' > "$R/etc/nethersec/apply.env"
runit --json
j 's["applier"]["enabled"] is True and s["applier"]["dry_run"] is True'
box; printf 'HOSTSEC_APPLY_ENABLED="1"\nHOSTSEC_APPLY_DRYRUN="0"\n' > "$R/etc/nethersec/apply.env"
runit --json
j 's["applier"]["enabled"] is True and s["applier"]["dry_run"] is False'
runit; a_has "applier: enabled yes, dry-run no"

# 5. an older systemctl without --timestamp: dates are parsed with date -d.
t "old-systemctl"
box; OLD=1
printf 'ExecMainStartTimestamp=%s\nResult=success\n' "$(date -u -d "@$((NOW - 600))" '+%a %Y-%m-%d %H:%M:%S UTC')" > "$WORK/sc/nethersec-security-report.service"
runit --json; OLD=0
j 's["timers"][0]["last_start"] == NOW - 600'

# 6. not installed: valid JSON with nothing in it, exit 0.
t "not-installed"
rm -rf "$R"; mkdir -p "$R"; runit --json
[ "$RC" = 0 ] && ok || bad "exit $RC"
j 's["installed"] is False and s["timers"] == [] and s["checks"] == [] and s["source"] is None'
j 's["transport"]["url"] == "missing" and s["detector"]["pending_security_updates"] is None'
runit; a_has "nethersec is not installed here"

# 7. garbled state never breaks the JSON.
t "garbled-state"
box; S="$R/var/lib/nethersec"
echo 'evil" severity 12x' > "$S/ev.security-updates"
echo 'not-a-number' > "$S/lastrun"
printf 'bad"name\tx\n' > "$S/first-seen.security-updates.tsv"
echo 'Web1"; rm' > "$S/unreadable"
printf 'HOSTSEC_SOURCE=Bad"Name\n' > "$R/etc/nethersec/report.env"
runit --json
j "$(check security-updates) == {\"part\": \"security-report\", \"event\": \"security-updates\", \"state\": \"raised\", \"severity\": None, \"asserted_at\": None}"
j 's["timers"][0]["last_done"] is None and s["source"] is None and s["detector"]["pending_security_updates"] == 0'

# 8. without root the mode-600 files cannot be read: "unknown", never a guess.
t "unreadable-env"
if [ "$(id -u)" -eq 0 ]; then
  echo "  (skipped unreadable-env: running as root, which reads mode-000 files anyway)"
else
  box; chmod 000 "$R/etc/nethersec/report.env" "$R/etc/nethersec/apply.env"
  runit --json
  j 's["transport"] == {"format": None, "url": "unknown", "key": "unknown"} and s["source"] is None'
  j 's["applier"]["dry_run"] is None and s["applier"]["enabled"] is None'
  chmod 600 "$R/etc/nethersec/report.env" "$R/etc/nethersec/apply.env"
fi

# 9. a state dir moved with HOSTSEC_STATE_DIR in report.env is read there.
t "moved-state-dir"
box; mkdir -p "$R/srv/ns-state"; echo "HOSTSEC_STATE_DIR=/srv/ns-state" >> "$R/etc/nethersec/report.env"
echo "warning $((NOW - 5))" > "$R/srv/ns-state/ev.ssh-auth-burst"
runit --json
j "$(check ssh-auth-burst)[\"state\"] == \"raised\" and $(check security-updates)[\"state\"] == \"ok\""

# 9b. the detector run by hand, with no unit installed: its checks are still listed.
t "hand-run"
box; rm -f "$R/etc/systemd/system/nethersec-security-report.service" "$R/etc/systemd/system/nethersec-security-report.timer"
runit --json
j 'not any(t["part"] == "security-report" for t in s["timers"])'
j "$(check security-updates)[\"state\"] == \"raised\" and $(check ssh-auth-burst)[\"state\"] == \"ok\""
rm -f "$R/var/lib/nethersec/lastrun"
runit --json
j 'not any(c["part"] == "security-report" for c in s["checks"])'

# 10. a bad argument.
t "bad-arg"
runit --yaml; [ "$RC" = 2 ] && ok || bad "expected exit 2, got $RC"

echo ""
echo "nethersec-status: $PASS passed, $FAIL failed"
rm -rf "$WORK" 2>/dev/null || :
[ "$FAIL" -eq 0 ]
