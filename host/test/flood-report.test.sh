#!/usr/bin/env sh
# flood-report.test.sh: offline behavioral harness for the box FLOOD / DDoS
# detector. Mocks conntrack files / ss / /proc/net/dev / docker / the HTTP
# aggregator / nft / the report transport via the script's env seams, and asserts
# the flood detection + DARK mitigation semantics with no real box and no network:
#   - quiet first run is silent (rate checks baseline, never alert on history)
#   - conntrack saturation, a SYN-recv burst, and a dominant established source each raise
#   - a dominant established peer that is a protected CDN range does NOT raise (fronting)
#   - mitigation is DARK by default: a would-drop is logged into the card, nft is NOT called
#   - mitigation ARMED drops via nft; an allow-listed / protected IP is spared
#   - inbound network volume raises over two runs (delta over the window)
#   - an HTTP request flood raises with the dominant client; console-format logs -> unreadable
#   - an SMTP connect burst raises with the dominant source
#   - a check with no signal on the box (no Caddy / no mailserver) is INERT, not unreadable
#   - unreadable folds into ONE monitor-unreadable-flood card (never a false all-clear)
#   - raise once then resolve; the kill switch + missing transport both exit 0 silently
#
#   sh host/test/flood-report.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../flood-report.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/frt.$$"); mkdir -p "$WORK"
BIN="$WORK/bin"; STATE="$WORK/state"; mkdir -p "$BIN" "$STATE"
CARDS="$WORK/cards.log"
NFTLOG="$WORK/nft.log"
NOW=1788000000
PASS=0; FAIL=0; CUR=""

# --- mocks -----------------------------------------------------------------
# report transport: record event|state|severity|detail.
cat > "$BIN/mock-report" <<'EOF'
#!/bin/sh
ev=""; st="triggered"; sv=""; dt=""
while [ $# -gt 0 ]; do
  case "$1" in
    --event) ev="$2"; shift 2 ;;
    --state) st="$2"; shift 2 ;;
    --severity) sv="$2"; shift 2 ;;
    --detail) dt="$2"; shift 2 ;;
    *) shift ;;
  esac
done
# every attempt is noted; report-down = no answer (exit 3), report-fail = an error
# answer (exit 1). Either way nothing is delivered.
printf '%s|%s\n' "$ev" "$st" >> "${MOCK_DIR:-/nonexistent}/attempts" 2>/dev/null
[ -f "${MOCK_DIR:-/nonexistent}/report-down" ] && exit 3
[ -f "${MOCK_DIR:-/nonexistent}/report-fail" ] && exit 1
printf 'E=%s|S=%s|V=%s|D=%s\n' "$ev" "$st" "$sv" "$dt" >> "$MOCK_CARDS"
exit 0
EOF
# ss: canned syn-recv / established output from files the test writes; fails with no
# output while $MOCK_DIR/ss-fail exists.
cat > "$BIN/ss" <<'EOF'
#!/bin/sh
[ -f "${MOCK_DIR:-/nonexistent}/ss-fail" ] && exit 1
case " $* " in
  *" syn-recv "*)    cat "${SS_SYN_FILE:-/dev/null}" 2>/dev/null ;;
  *" established "*) cat "${SS_ESTAB_FILE:-/dev/null}" 2>/dev/null ;;
esac
exit 0
EOF
# docker: `ps --format` prints $DOCKER_PS; `logs` prints $DOCKER_LOGS_FILE. Like a
# stopped daemon, `ps` fails while $MOCK_DIR/docker-ps-fail exists and `logs` while
# $MOCK_DIR/docker-logs-fail does, each with no output.
cat > "$BIN/docker" <<'EOF'
#!/bin/sh
case "${1:-}" in
  ps)   [ -f "${MOCK_DIR:-/nonexistent}/docker-ps-fail" ] && exit 1
        printf '%s' "${DOCKER_PS:-}" ; [ -n "${DOCKER_PS:-}" ] && printf '\n' ;;
  logs) [ -f "${MOCK_DIR:-/nonexistent}/docker-logs-fail" ] && { echo "Error response from daemon" >&2; exit 1; }
        cat "${DOCKER_LOGS_FILE:-/dev/null}" 2>/dev/null ;;
esac
exit 0
EOF
# http aggregator: echo a canned "total top ip share lines exempt" line ($AGG_OUT); the real
# one prints "0 0 - 0 0 0" for no input. Fails with no output while $MOCK_DIR/agg-fail
# exists, like the real one when it cannot run.
cat > "$BIN/mock-agg" <<'EOF'
#!/bin/sh
cat >/dev/null 2>&1
[ -f "${MOCK_DIR:-/nonexistent}/agg-fail" ] && exit 1
printf '%s\n' "${AGG_OUT:-0 0 - 0 0 0}"
EOF
# nft: `list table` -> absent (exit 1) so _apply_drop creates it; `-f -` -> consume
# stdin ok; `add element` -> record. Everything logged so we can assert calls.
cat > "$BIN/nft" <<'EOF'
#!/bin/sh
printf 'nft %s\n' "$*" >> "$NFT_LOG"
case "${1:-}" in
  list) exit 1 ;;
  -f)   cat >/dev/null 2>&1; exit 0 ;;
  *)    exit 0 ;;
esac
EOF
# ip: the box's own address 198.51.100.10 and its gateway 198.51.100.1. Fails while
# $MOCK_DIR/ip-fail exists.
cat > "$BIN/ip" <<'EOF'
#!/bin/sh
[ -f "${MOCK_DIR:-/nonexistent}/ip-fail" ] && exit 1
case "$*" in
  *addr*)  echo '2: eth0    inet 198.51.100.10/24 brd 198.51.100.255 scope global eth0\       valid_lft forever preferred_lft forever' ;;
  *route*) echo 'default via 198.51.100.1 dev eth0 proto static' ;;
esac
exit 0
EOF
chmod +x "$BIN"/mock-report "$BIN"/ss "$BIN"/docker "$BIN"/mock-agg "$BIN"/nft "$BIN"/ip

# helper: write a /proc/net/dev-style file for eth0 with rx bytes/packets.
mk_netdev() { # file rxbytes rxpackets
  {
    echo "Inter-|   Receive                                                |  Transmit"
    echo " face |bytes    packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed"
    printf '  eth0: %s %s 0 0 0 0 0 0 5000 50 0 0 0 0 0 0\n' "$2" "$3"
  } > "$1"
}

# default per-test config (overridden inside each test before runit)
setup() {
  rm -rf "$STATE"; mkdir -p "$STATE"
  : > "$CARDS"; : > "$NFTLOG"
  CT_CNT="$WORK/ct.count"; CT_MAX="$WORK/ct.max"; echo 100 > "$CT_CNT"; echo 262144 > "$CT_MAX"
  SS_SYN="$WORK/ss.syn"; : > "$SS_SYN"
  SS_ESTAB="$WORK/ss.estab"; : > "$SS_ESTAB"
  NETDEV="$WORK/netdev"; mk_netdev "$NETDEV" 1000000 1000
  DPS=""                    # docker ps output (container names)
  DLOGS="$WORK/dlogs"; : > "$DLOGS"
  AGGOUT="0 0 - 0 0 0"
  MIT=0; ALLOW=""
  RUN_NOW="$NOW"
  # thresholds: keep them out of the way unless a test sets them
  CT_PCT=85; SYN=500; EST_MIN=3000; EST_SHARE=60
  P_PPS=120000; P_MBPS=800
  H_MIN=6000; H_SHARE=55
  S_MIN=1500; S_SHARE=60
  MAXP=6; rm -f "$WORK/report-fail" "$WORK/report-down" "$WORK/attempts"
  rm -f "$WORK/ss-fail" "$WORK/docker-ps-fail" "$WORK/docker-logs-fail" "$WORK/agg-fail" "$WORK/ip-fail"
}

runit() {
  env \
    HOSTSEC_FLOOD_KILL_FILE="$WORK/nokill" \
    HOSTSEC_FLOOD_SOURCE=testbox \
    HOSTSEC_FLOOD_REPORT_SCRIPT="$BIN/mock-report" \
    HOSTSEC_FLOOD_STATE_DIR="$STATE" \
    HOSTSEC_FLOOD_NOW="$RUN_NOW" \
    HOSTSEC_FLOOD_SS_CMD="$BIN/ss" \
    HOSTSEC_FLOOD_IP_CMD="$BIN/ip" \
    HOSTSEC_FLOOD_DOCKER_CMD="$BIN/docker" \
    HOSTSEC_FLOOD_NFT_CMD="$BIN/nft" \
    HOSTSEC_FLOOD_HTTP_AGG_CMD="$BIN/mock-agg" \
    HOSTSEC_FLOOD_NETDEV_FILE="$NETDEV" \
    HOSTSEC_FLOOD_CONNTRACK_COUNT_FILE="$CT_CNT" \
    HOSTSEC_FLOOD_CONNTRACK_MAX_FILE="$CT_MAX" \
    HOSTSEC_FLOOD_NET_IFACE=eth0 \
    HOSTSEC_FLOOD_CONNTRACK_PCT="$CT_PCT" \
    HOSTSEC_FLOOD_SYNRECV="$SYN" \
    HOSTSEC_FLOOD_ESTAB_MIN="$EST_MIN" \
    HOSTSEC_FLOOD_ESTAB_SHARE_PCT="$EST_SHARE" \
    HOSTSEC_FLOOD_PPS="$P_PPS" \
    HOSTSEC_FLOOD_MBPS="$P_MBPS" \
    HOSTSEC_FLOOD_HTTP_MIN="$H_MIN" \
    HOSTSEC_FLOOD_HTTP_SHARE_PCT="$H_SHARE" \
    HOSTSEC_FLOOD_SMTP_MIN="$S_MIN" \
    HOSTSEC_FLOOD_SMTP_SHARE_PCT="$S_SHARE" \
    HOSTSEC_FLOOD_MITIGATE="$MIT" \
    HOSTSEC_FLOOD_MITIGATE_MINUTES=60 \
    HOSTSEC_FLOOD_ALLOW_IPS="$ALLOW" \
    HOSTSEC_FLOOD_MAX_POSTS="$MAXP" \
    NETHERSEC_REPORT_URL="http://x/report" NETHERSEC_REPORT_KEY="y" \
    MOCK_CARDS="$CARDS" MOCK_DIR="$WORK" NFT_LOG="$NFTLOG" \
    SS_SYN_FILE="$SS_SYN" SS_ESTAB_FILE="$SS_ESTAB" \
    DOCKER_PS="$DPS" DOCKER_LOGS_FILE="$DLOGS" AGG_OUT="$AGGOUT" \
    PATH="$BIN:$PATH" \
    sh "$SCRIPT" 2>"$WORK/stderr"
  RC=$?
}

# --- assertions ------------------------------------------------------------
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; }
a_exit0()      { [ "$RC" = 0 ] && ok || bad "expected exit 0, got $RC"; }
a_no_cards()   { [ -s "$CARDS" ] && bad "expected NO cards, got: $(tr '\n' ' ' <"$CARDS")" || ok; }
a_card()       { grep -q "E=$1|" "$CARDS" 2>/dev/null && ok || bad "expected a card for '$1' (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_no_card()    { grep -q "E=$1|" "$CARDS" 2>/dev/null && bad "unexpected card for '$1' (got: $(tr '\n' ' ' <"$CARDS"))" || ok; }
a_card_sev()   { grep -q "E=$1|S=[^|]*|V=$2" "$CARDS" 2>/dev/null && ok || bad "expected '$1' at severity '$2' (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_card_state() { grep -q "E=$1|S=$2|" "$CARDS" 2>/dev/null && ok || bad "expected '$1' state '$2' (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_detail_has() { d=$(grep "E=$1|" "$CARDS" 2>/dev/null | sed 's/.*|D=//'); printf '%s' "$d" | grep -qF "$2" && ok || bad "expected '$1' detail to contain '$2' (got: $d)"; }
a_nft_add()    { grep -q "add element" "$NFTLOG" 2>/dev/null && ok || bad "expected an nft add-element call (got: $(tr '\n' ';' <"$NFTLOG"))"; }
a_no_nft_add() { grep -q "add element" "$NFTLOG" 2>/dev/null && bad "unexpected nft add-element call" || ok; }

# ===========================================================================
# 1. quiet first run -> silent (rate checks baseline; conn reads low; no signal)
t "quiet-first-run"
setup
runit; a_exit0; a_no_cards

# 2. conntrack saturation -> conn-flood warning card
t "conntrack-saturation"
setup
echo 240000 > "$CT_CNT"          # 240000/262144 = 91% >= 85
runit; a_card_sev conn-flood warning; a_detail_has conn-flood 'conntrack'

# 3. SYN-recv burst -> conn-flood card names the SYN flood
t "synrecv-burst"
setup
i=0; while [ "$i" -lt 800 ]; do echo "SYN-RECV 0 0 10.0.0.1:443 198.51.100.66:$i" >> "$SS_SYN"; i=$((i+1)); done
runit; a_card conn-flood; a_detail_has conn-flood 'syn-recv=800'

# 4. dominant established source (non-CDN) -> conn-flood card + DARK would-drop note; NO nft
t "estab-dominant-dryrun"
setup
EST_MIN=5; EST_SHARE=60
i=0; while [ "$i" -lt 10 ]; do echo "ESTAB 0 0 10.0.0.1:443 203.0.113.99:$((1000+i))" >> "$SS_ESTAB"; i=$((i+1)); done
runit; a_card conn-flood; a_detail_has conn-flood '203.0.113.99 holds 10/10'
a_detail_has conn-flood 'would drop 203.0.113.99'; a_no_nft_add

# 5. dominant established peer is a CDN range -> NOT an attack, NO card (expected fronting)
t "estab-dominant-cdn-suppressed"
setup
EST_MIN=5; EST_SHARE=60
i=0; while [ "$i" -lt 10 ]; do echo "ESTAB 0 0 10.0.0.1:443 104.16.0.9:$((1000+i))" >> "$SS_ESTAB"; i=$((i+1)); done
runit; a_no_card conn-flood

# 6. mitigation ARMED -> nft drop of the dominant IP; detail says auto-dropped
t "estab-dominant-armed-nft"
setup
EST_MIN=5; EST_SHARE=60; MIT=1
i=0; while [ "$i" -lt 10 ]; do echo "ESTAB 0 0 10.0.0.1:443 203.0.113.99:$((1000+i))" >> "$SS_ESTAB"; i=$((i+1)); done
runit; a_card conn-flood; a_nft_add; a_detail_has conn-flood 'auto-dropped 203.0.113.99'

# 7. mitigation ARMED but the dominant IP is allow-listed -> spared, NO nft
t "estab-dominant-allowlisted"
setup
EST_MIN=5; EST_SHARE=60; MIT=1; ALLOW="203.0.113.99"
i=0; while [ "$i" -lt 10 ]; do echo "ESTAB 0 0 10.0.0.1:443 203.0.113.99:$((1000+i))" >> "$SS_ESTAB"; i=$((i+1)); done
runit; a_card conn-flood; a_no_nft_add; a_detail_has conn-flood 'allow-listed'

# 8. inbound network volume: run1 baselines, run2 past threshold -> net-flood
t "net-volume-two-runs"
setup
P_PPS=1000; P_MBPS=1
mk_netdev "$NETDEV" 1000000 1000
RUN_NOW="$NOW"; runit; a_no_card net-flood         # baseline
: > "$CARDS"
mk_netdev "$NETDEV" 9000000000 8000000            # +~9GB, +8M pkts over 60s
RUN_NOW="$((NOW + 60))"; runit
a_card_sev net-flood warning; a_detail_has net-flood 'pkts/s'

# 9. HTTP flood: caddy present + aggregator reports a dominant client -> http-flood
t "http-flood"
setup
DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55
echo '{"msg":"handled request"}' > "$DLOGS"          # non-empty so logs read
AGGOUT="8000 6000 203.0.113.4 75 8000 0"
RUN_NOW="$NOW"; runit                                 # first run baselines (LAST=0)
: > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_card http-flood; a_detail_has http-flood '203.0.113.4 sent 6000/8000'; a_detail_has http-flood 'would drop 203.0.113.4'

# 9b. SECURITY: mitigation ARMED but the dominant IP is malformed (a comma-list /
#     injection) -> strictly refused BEFORE nft, so no non-expiring drop is ever added.
#     mitigate_ip requires a single valid IPv4.
t "http-flood-armed-invalid-ip-refused"
setup
DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55; MIT=1
echo '{"msg":"handled request"}' > "$DLOGS"
AGGOUT="8000 6000 203.0.113.4,198.51.100.8 75 8000 0"
RUN_NOW="$NOW"; runit                                 # first run baselines (LAST=0)
: > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_card http-flood; a_no_nft_add; a_detail_has http-flood 'not a valid IPv4'

# 9c. a dominant client the aggregator marks exempt (a CDN address, or one that mostly
#     claims a good-bot User-Agent) still raises, and is never blocked, even when armed.
t "http-flood-exempt-source-alerts-not-blocked"
setup
DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55; MIT=1
echo '{"msg":"handled request"}' > "$DLOGS"
AGGOUT="8000 6000 203.0.113.4 75 8000 1"
RUN_NOW="$NOW"; runit
: > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_card http-flood; a_no_nft_add; a_detail_has http-flood 'not blocked: 203.0.113.4'

# 9d. many sources, none over the share: raises on the total rate (18000/min by default)
#     and blocks nothing, even when armed.
t "http-flood-many-sources-alerts-not-blocked"
setup
DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55; MIT=1
echo '{"msg":"handled request"}' > "$DLOGS"
AGGOUT="20000 2000 203.0.113.4 10 20000 0"
RUN_NOW="$NOW"; runit
: > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_card http-flood; a_no_nft_add; a_detail_has http-flood 'no single source over 55%'

# 9e. busy but under the total rate, with no dominant client: no card.
t "http-busy-under-total-rate-quiet"
setup
DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55
echo '{"msg":"handled request"}' > "$DLOGS"
AGGOUT="10000 1000 203.0.113.4 10 10000 0"
RUN_NOW="$NOW"; runit
: > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_no_card http-flood

# 9g. SECURITY: armed, a dominant source that is loopback, private, the box's own address
#     or its gateway is never dropped (a proxy or tunnel in front of Caddy shows up as one
#     of these, and a drop would cut the box off from itself). Same when `ip` fails.
for case_ip in 127.0.0.1 10.1.2.3 100.64.0.9 198.51.100.10 198.51.100.1 ip-fail; do
  t "http-flood-armed-never-drops-$case_ip"
  setup
  DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55; MIT=1
  echo '{"msg":"handled request"}' > "$DLOGS"
  drop_ip="$case_ip"
  [ "$case_ip" = ip-fail ] && { drop_ip=203.0.113.4; : > "$WORK/ip-fail"; }
  AGGOUT="8000 6000 $drop_ip 75 8000 0"
  RUN_NOW="$NOW"; runit
  : > "$CARDS"
  RUN_NOW="$((NOW + 60))"; runit
  a_card http-flood; a_no_nft_add; a_detail_has http-flood "$drop_ip is a local, private or own address"
done
# and a public address that is none of those is still dropped when armed
t "http-flood-armed-drops-public"
setup
DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55; MIT=1
echo '{"msg":"handled request"}' > "$DLOGS"
AGGOUT="8000 6000 203.0.113.4 75 8000 0"
RUN_NOW="$NOW"; runit
: > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_card http-flood; a_nft_add

# 9f. the same total spread over a long window (a pause) is a low rate: no card.
t "http-total-over-long-window-quiet"
setup
DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55
echo '{"msg":"handled request"}' > "$DLOGS"
AGGOUT="20000 2000 203.0.113.4 10 20000 0"
RUN_NOW="$NOW"; runit
: > "$CARDS"
RUN_NOW="$((NOW + 3600))"; runit
a_no_card http-flood

# 10. HTTP console-format log (lines seen, none parsed) -> unreadable, folds; NO http-flood
t "http-console-unreadable"
setup
DPS="web-caddy-1"
echo 'plain console line' > "$DLOGS"
AGGOUT="0 0 - 0 500 0"                                  # 500 lines seen, 0 parsed
RUN_NOW="$NOW"; runit
: > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_no_card http-flood; a_card monitor-unreadable-flood

# 11. no Caddy container -> HTTP check INERT (no card, not unreadable)
t "http-inert-no-caddy"
setup
DPS="somethingelse"                                  # no *caddy* / no *mail*
AGGOUT="8000 6000 203.0.113.4 75 8000 0"
RUN_NOW="$NOW"; runit; : > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_no_card http-flood; a_no_card monitor-unreadable-flood

# 12. SMTP connect burst -> smtp-flood card with the dominant source
t "smtp-flood"
setup
DPS="mailserver"; S_MIN=100; S_SHARE=60
i=0; while [ "$i" -lt 200 ]; do echo "$(printf 'Sep 21 postfix/smtpd[1]: connect from bad[203.0.113.77]')" >> "$DLOGS"; i=$((i+1)); done
RUN_NOW="$NOW"; runit; : > "$CARDS"
RUN_NOW="$((NOW + 60))"; runit
a_card smtp-flood; a_detail_has smtp-flood '200 connects'; a_detail_has smtp-flood '203.0.113.77'

# 13. raise then resolve: conntrack high -> card; next run normal -> resolved card
t "raise-then-resolve"
setup
echo 240000 > "$CT_CNT"
RUN_NOW="$NOW"; runit; a_card_state conn-flood triggered
: > "$CARDS"
echo 100 > "$CT_CNT"
RUN_NOW="$((NOW + 120))"; runit; a_card_state conn-flood resolved

# 14. kill switch -> silent, exit 0
t "kill-switch"
setup
: > "$WORK/killnow"
env HOSTSEC_FLOOD_KILL_FILE="$WORK/killnow" HOSTSEC_FLOOD_STATE_DIR="$STATE" \
    HOSTSEC_FLOOD_REPORT_SCRIPT="$BIN/mock-report" MOCK_CARDS="$CARDS" \
    NETHERSEC_REPORT_URL="http://x/report" NETHERSEC_REPORT_KEY="y" \
    PATH="$BIN:$PATH" sh "$SCRIPT" 2>/dev/null; RC=$?
a_exit0; a_no_cards

# 15. missing transport secret -> exit 0, silent
t "no-transport-secret"
setup
env HOSTSEC_FLOOD_KILL_FILE="$WORK/nokill" HOSTSEC_FLOOD_STATE_DIR="$STATE" \
    HOSTSEC_FLOOD_REPORT_SCRIPT="$BIN/mock-report" MOCK_CARDS="$CARDS" \
    NETHERSEC_REPORT_URL="" NETHERSEC_REPORT_KEY="" \
    PATH="$BIN:$PATH" sh "$SCRIPT" 2>/dev/null; RC=$?
a_exit0; a_no_cards

# 16. delivery: only a 2xx counts as sent. A raise or a resolve that was not delivered
#     goes again on the next run, a delivered one is not sent twice, the per-run cap
#     leaves the rest for the next run, and no answer at all stops the run's posts.
a_attempts()  { n=$(wc -l < "$WORK/attempts" 2>/dev/null | tr -d ' '); [ "${n:-0}" = "$1" ] && ok || bad "expected $1 post attempt(s), got ${n:-0}"; }
a_state()     { [ -f "$STATE/flood-ev.$1" ] && ok || bad "expected the state file flood-ev.$1"; }
a_no_state()  { [ -f "$STATE/flood-ev.$1" ] && bad "flood-ev.$1 must not exist" || ok; }
a_log_has()   { grep -qF -- "$1" "$WORK/stderr" && ok || bad "expected the log to say '$1' (got: $(tr '\n' ' ' < "$WORK/stderr"))"; }
t "delivery-raise-retried"
setup
echo 240000 > "$CT_CNT"
: > "$WORK/report-fail"; runit; a_exit0; a_no_cards; a_no_state conn-flood; a_log_has "post failed"
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + 60))"; runit; a_card_state conn-flood triggered; a_state conn-flood
: > "$CARDS"; RUN_NOW="$((NOW + 120))"; runit; a_no_cards

t "delivery-raise-failed-then-cleared"
setup
echo 240000 > "$CT_CNT"
: > "$WORK/report-fail"; runit; a_no_cards
rm -f "$WORK/report-fail"; echo 100 > "$CT_CNT"; RUN_NOW="$((NOW + 60))"; runit; a_no_cards

t "delivery-resolve-retried"
setup
echo 240000 > "$CT_CNT"
runit; a_card_state conn-flood triggered
echo 100 > "$CT_CNT"; : > "$CARDS"; : > "$WORK/report-fail"; RUN_NOW="$((NOW + 60))"; runit
a_no_cards; a_state conn-flood
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + 120))"; runit; a_card_state conn-flood resolved; a_no_state conn-flood
: > "$CARDS"; RUN_NOW="$((NOW + 180))"; runit; a_no_cards

t "delivery-cap-rest-next-run"
setup; MAXP=1
echo 240000 > "$CT_CNT"; NETDEV="$WORK/no-netdev"          # conn-flood, and net-flood unreadable
runit; a_card conn-flood; a_no_card monitor-unreadable-flood
a_log_has "per-run post cap (1) hit; 1 report(s) suppressed this run"
: > "$CARDS"; RUN_NOW="$((NOW + 60))"; runit; a_card monitor-unreadable-flood; a_no_card conn-flood
: > "$CARDS"; RUN_NOW="$((NOW + 120))"; runit; a_no_cards

t "delivery-no-answer-defers-the-rest"
setup
echo 240000 > "$CT_CNT"; NETDEV="$WORK/no-netdev"
: > "$WORK/report-down"; runit; a_exit0; a_no_cards; a_attempts 1
a_log_has "the hub did not answer; 1 more report(s) wait for the next run"
rm -f "$WORK/report-down"; RUN_NOW="$((NOW + 60))"; runit; a_card conn-flood; a_card monitor-unreadable-flood

# 17. cannot read is never all-clear: an open http-flood card stays open when a later
#     run cannot read Caddy's log. A `docker logs` that fails (the aggregator then sees no
#     input and prints "0 0 - 0 0 0"), a `docker ps` that fails (it cannot tell "no Caddy"
#     from "Caddy it cannot see"), an aggregator that fails, or a garbled aggregator line
#     each fold into monitor-unreadable-flood and send no resolve.
http_raised() {  # an http-flood card raised on the second run
  setup
  DPS="web-caddy-1"; H_MIN=5000; H_SHARE=55
  echo '{"msg":"handled request"}' > "$DLOGS"
  AGGOUT="8000 6000 203.0.113.4 75 8000 0"
  RUN_NOW="$NOW"; runit
  RUN_NOW="$((NOW + 60))"; runit; a_card_state http-flood triggered; a_state http-flood
  : > "$CARDS"; AGGOUT="0 0 - 0 0 0"; RUN_NOW="$((NOW + 120))"
}
for how in docker-logs-fail docker-ps-fail agg-fail; do
  t "http-unreadable-keeps-card-$how"
  http_raised; : > "$WORK/$how"
  runit; a_exit0; a_no_card http-flood; a_state http-flood
  a_card monitor-unreadable-flood; a_detail_has monitor-unreadable-flood 'http-flood'
  rm -f "$WORK/$how"
  : > "$CARDS"; RUN_NOW="$((NOW + 180))"; runit
  a_card_state http-flood resolved; a_card_state monitor-unreadable-flood resolved
done
t "http-garbled-aggregator-line-unreadable"
http_raised; AGGOUT="garbage"
runit; a_no_card http-flood; a_state http-flood; a_card monitor-unreadable-flood
# a box that really has no Caddy container (docker ps works) stays inert
t "http-no-caddy-still-inert"
setup; DPS="somethingelse"
RUN_NOW="$NOW"; runit; : > "$CARDS"; RUN_NOW="$((NOW + 60))"; runit; a_no_cards

# 18. the same for the SMTP check: a failed `docker ps` is not "no mail server", and a
#     failed `docker logs` keeps the open card too.
for how in docker-ps-fail docker-logs-fail; do
  t "smtp-unreadable-keeps-card-$how"
  setup; DPS="mailserver"; S_MIN=100; S_SHARE=60
  i=0; while [ "$i" -lt 200 ]; do echo 'Sep 21 postfix/smtpd[1]: connect from bad[203.0.113.77]' >> "$DLOGS"; i=$((i+1)); done
  RUN_NOW="$NOW"; runit
  RUN_NOW="$((NOW + 60))"; runit; a_card_state smtp-flood triggered
  : > "$CARDS"; : > "$WORK/$how"; RUN_NOW="$((NOW + 120))"; runit
  a_no_card smtp-flood; a_state smtp-flood; a_card monitor-unreadable-flood; a_detail_has monitor-unreadable-flood 'smtp-flood'
done

# 19. a failed `ss` is not a read. With the conntrack leg off it is the only source, so
#     the check is unreadable, never "ok". With conntrack readable and low, an open card
#     that the established leg raised is still not resolved: ss's legs are unknown.
t "ss-fails-no-conntrack-unreadable"
setup; CT_PCT=0; : > "$WORK/ss-fail"
runit; a_exit0; a_no_card conn-flood; a_card monitor-unreadable-flood; a_detail_has monitor-unreadable-flood 'conn-flood'
t "ss-fails-keeps-estab-card"
setup; EST_MIN=5; EST_SHARE=60
i=0; while [ "$i" -lt 10 ]; do echo "ESTAB 0 0 10.0.0.1:443 203.0.113.99:$((1000+i))" >> "$SS_ESTAB"; i=$((i+1)); done
runit; a_card_state conn-flood triggered
: > "$CARDS"; : > "$WORK/ss-fail"; RUN_NOW="$((NOW + 60))"; runit
a_no_card conn-flood; a_state conn-flood; a_card monitor-unreadable-flood
# ...but a flood the conntrack leg reads on its own still raises while ss fails
t "ss-fails-conntrack-still-raises"
setup; echo 240000 > "$CT_CNT"; : > "$WORK/ss-fail"
runit; a_card_sev conn-flood warning; a_detail_has conn-flood 'conntrack'; a_no_card monitor-unreadable-flood
# a quiet box with zero sockets in either state reads fine (ss answered, nothing there)
t "ss-zero-sockets-is-a-read"
setup; CT_PCT=0
runit; a_no_cards

# 20. only the exact value 1 arms the blocking: "true", "yes" or an empty value leaves it
#     off (logged, named a would-drop on the card) and never calls nft.
for v in true yes ""; do
  t "mitigate-only-exact-one-arms-'$v'"
  setup; EST_MIN=5; EST_SHARE=60; MIT="$v"
  i=0; while [ "$i" -lt 10 ]; do echo "ESTAB 0 0 10.0.0.1:443 203.0.113.99:$((1000+i))" >> "$SS_ESTAB"; i=$((i+1)); done
  runit; a_card conn-flood; a_no_nft_add; a_detail_has conn-flood 'would drop 203.0.113.99'
  a_log_has "HOSTSEC_FLOOD_MITIGATE='$v' is not 0 or 1; blocking stays off (only 1 arms it)"
done

# ===========================================================================
echo ""
echo "flood-report: $PASS passed, $FAIL failed"
rm -rf "$WORK" 2>/dev/null || :
[ "$FAIL" -eq 0 ]
