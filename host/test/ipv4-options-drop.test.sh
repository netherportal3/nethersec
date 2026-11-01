#!/usr/bin/env sh
# ipv4-options-drop.test.sh: offline harness for ipv4-options-drop.sh. Mocks nft and
# systemctl through the script's env seams and points it at scratch /etc dirs, so it
# needs no nftables, no root and no network. Asserts:
#   - apply writes the rules + unit, checks the rules with `nft -c` first, enables and
#     starts the unit, and ends with the table loaded
#   - the rules drop only IPv4 TCP with a header longer than 5 words, at raw prerouting,
#     and replace an old copy of the table instead of adding to it
#   - rules nft rejects change nothing: no file, no unit, no start
#   - a unit that runs but leaves no table is an error, not a silent success
#   - --check passes only with the table loaded AND the unit enabled, and writes nothing
#   - an unreadable ruleset (not root) is an error, not "not loaded"
#   - --remove stops the unit, deletes the table and both files
#   - re-running apply is safe
#
#   sh host/test/ipv4-options-drop.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../ipv4-options-drop.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }
command -v bash >/dev/null 2>&1 || { echo "ipv4-options-drop.test: bash is required"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/iod.$$"); mkdir -p "$WORK"
BIN="$WORK/bin"; mkdir -p "$BIN"
ETC="$WORK/etc-nethersec"; UNITS="$WORK/units"

# nft: the table is "loaded" while $MOCK_DIR/loaded exists. `-c -f` passes unless
# $MOCK_DIR/reject exists; `list tables` fails while $MOCK_DIR/noread exists.
cat > "$BIN/nft" <<'EOF'
#!/bin/sh
echo "$*" >> "$MOCK_DIR/nft.log"
case "$*" in
  "list tables") [ -f "$MOCK_DIR/noread" ] && exit 1; exit 0 ;;
  "-c -f "*) [ -f "$MOCK_DIR/reject" ] && { echo "Error: syntax error"; exit 1; }; exit 0 ;;
  "-f "*) [ -f "$MOCK_DIR/noload" ] || touch "$MOCK_DIR/loaded"; exit 0 ;;
  "list table ip nethersec_ipopt") [ -f "$MOCK_DIR/loaded" ] ;;
  "list counter ip nethersec_ipopt dropped") [ -f "$MOCK_DIR/loaded" ] && echo "	counter dropped { packets 7 bytes 420 }" ;;
  "delete table ip nethersec_ipopt") [ -f "$MOCK_DIR/loaded" ] && rm -f "$MOCK_DIR/loaded" ;;
  *) exit 1 ;;
esac
EOF
# systemctl: logged. enable/disable flip $MOCK_DIR/enabled; restart runs the unit's
# ExecStart and disable --now its ExecStop, through the mock nft.
cat > "$BIN/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$MOCK_DIR/systemctl.log"
case "$*" in
  "is-enabled "*) [ -f "$MOCK_DIR/enabled" ] && { echo enabled; exit 0; }; echo disabled; exit 1 ;;
  "enable "*) touch "$MOCK_DIR/enabled" ;;
  "disable --now "*) rm -f "$MOCK_DIR/enabled"; "$MOCK_NFT" delete table ip nethersec_ipopt ;;
  "restart "*) "$MOCK_NFT" -f "$MOCK_ETC/ipv4-options-drop.nft" ;;
esac
exit 0
EOF
chmod +x "$BIN/nft" "$BIN/systemctl"

PASS=0; FAIL=0; CUR=""
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; }

setup() {
  rm -rf "$ETC" "$UNITS"
  rm -f "$WORK/loaded" "$WORK/enabled" "$WORK/reject" "$WORK/noload" "$WORK/noread" "$WORK/nft.log" "$WORK/systemctl.log"
}
run() {
  MOCK_DIR="$WORK" MOCK_NFT="$BIN/nft" MOCK_ETC="$ETC" \
  HOSTSEC_NFT_CMD="$BIN/nft" HOSTSEC_SYSTEMCTL_CMD="$BIN/systemctl" \
  HOSTSEC_ETC_DIR="$ETC" HOSTSEC_UNIT_DIR="$UNITS" \
    bash "$SCRIPT" "$@" > "$WORK/out" 2>&1
  RC=$?
}
RULES="$ETC/ipv4-options-drop.nft"
UNIT="$UNITS/nethersec-ipv4-options-drop.service"

t "apply turns it on"
setup; run
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"
[ -f "$WORK/loaded" ] && ok || bad "table not loaded"
[ -f "$WORK/enabled" ] && ok || bad "unit not enabled"
grep -q '^-c -f ' "$WORK/nft.log" && ok || bad "rules not checked with nft -c"
[ "$(grep -n '^-c -f ' "$WORK/nft.log" | head -1 | cut -d: -f1)" -lt "$(grep -n '^-f ' "$WORK/nft.log" | head -1 | cut -d: -f1)" ] && ok || bad "nft -c did not run before the load"
grep -q 'daemon-reload' "$WORK/systemctl.log" && ok || bad "no daemon-reload"
grep -q "ExecStart=$BIN/nft -f $RULES" "$UNIT" && ok || bad "unit ExecStart wrong: $(grep ExecStart "$UNIT")"
grep -q '^WantedBy=sysinit.target' "$UNIT" && ok || bad "unit not wanted at boot"
grep -q '^Before=network-pre.target' "$UNIT" && ok || bad "unit not ordered before the network"

t "the rules drop only IPv4 TCP with IP options, at raw prerouting"
grep -q 'ip hdrlength != 5 meta l4proto tcp counter name "dropped" drop' "$RULES" && ok || bad "drop rule missing"
grep -q 'type filter hook prerouting priority raw; policy accept;' "$RULES" && ok || bad "chain hook/policy wrong"
[ "$(grep -c ' drop$' "$RULES")" -eq 1 ] && ok || bad "more than one drop rule"
grep -q '^table ip nethersec_ipopt$' "$RULES" && grep -q '^delete table ip nethersec_ipopt$' "$RULES" && ok || bad "reload would not replace the table"
grep -q 'ip6\|inet ' "$RULES" && bad "touches IPv6" || ok

t "re-running apply is safe"
run
[ "$RC" -eq 0 ] && [ -f "$WORK/loaded" ] && ok || bad "second apply failed: $(cat "$WORK/out")"

t "--check passes when loaded and enabled, and shows the counter"
cp "$RULES" "$WORK/rules.before"
run --check
[ "$RC" -eq 0 ] && ok || bad "check exit $RC: $(cat "$WORK/out")"
grep -q '7 packets dropped' "$WORK/out" && ok || bad "counter not shown: $(cat "$WORK/out")"
cmp -s "$RULES" "$WORK/rules.before" && ok || bad "--check rewrote the rules"

t "--check fails when the unit is not enabled"
rm -f "$WORK/enabled"; run --check
[ "$RC" -eq 1 ] && grep -q 'NOT enabled' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"

t "--check fails when the table is not loaded"
touch "$WORK/enabled"; rm -f "$WORK/loaded"; run --check
[ "$RC" -eq 1 ] && grep -q 'NOT loaded' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"

t "an unreadable ruleset is an error, not 'not loaded'"
touch "$WORK/noread"; run --check
[ "$RC" -eq 1 ] && grep -q 'run as root' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"
grep -q 'NOT loaded' "$WORK/out" && bad "reported a false 'not loaded'" || ok

t "rules nft rejects change nothing"
setup; touch "$WORK/reject"; run
[ "$RC" -eq 1 ] && ok || bad "exit $RC"
[ ! -f "$RULES" ] && [ ! -f "$UNIT" ] && ok || bad "files written despite the reject"
[ ! -f "$WORK/systemctl.log" ] && ok || bad "systemctl ran: $(cat "$WORK/systemctl.log")"
ls "$ETC" 2>/dev/null | grep -q tmp && bad "temp file left behind" || ok

t "a unit that leaves no table is an error"
setup; touch "$WORK/noload"; run
[ "$RC" -eq 1 ] && grep -q 'table is not loaded' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"

t "--remove takes it all off"
setup; run; run --remove
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"
[ ! -f "$WORK/loaded" ] && ok || bad "table still loaded"
[ ! -f "$WORK/enabled" ] && ok || bad "unit still enabled"
[ ! -f "$RULES" ] && [ ! -f "$UNIT" ] && ok || bad "files left behind"

t "--remove when nothing is installed is fine"
setup; run --remove
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"

t "unknown arg"
setup; run --bogus
[ "$RC" -eq 2 ] && ok || bad "exit $RC"

rm -rf "$WORK"
echo "ipv4-options-drop.test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
