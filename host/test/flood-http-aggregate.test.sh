#!/usr/bin/env sh
# flood-http-aggregate.test.sh: offline test for the Caddy-JSON HTTP aggregator.
# Feeds canned Caddy access-log JSON on stdin and asserts the "total top ip share
# lines exempt" output: CF-Connecting-IP preference, good-bot UA + protected-CDN exemption, the
# dominant-source pick, and the console-format signal (lines seen, none parsed).
#
#   sh host/test/flood-http-aggregate.test.sh
#
# Exit 0 = all asserts passed. Needs python3 (stdlib only).
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
AGG="$HERE/../flood-http-aggregate.py"
[ -f "$AGG" ] || { echo "cannot find $AGG"; exit 2; }
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "SKIP: no $PY on PATH"; exit 0; }

PASS=0; FAIL=0; CUR=""
WORK_IN=$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/fhat.$$")
t()   { CUR="$1"; }
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
# run <stdin>; capture the aggregator's single output line. Strip CR so a Windows
# python (CRLF stdout) dev host compares equal to a Linux box (LF) and CI.
run() { OUT=$(printf '%s' "$1" | "$PY" "$AGG" 2>/dev/null | tr -d '\r'); }
a_eq() { [ "$OUT" = "$1" ] && ok || bad "expected [$1], got [$OUT]"; }

acc() { # helper: one access-log line for client_ip $1, optional CF ip $2, UA $3
  ci="$1"; cf="${2:-}"; ua="${3:-curl/8}"
  h="\"User-Agent\":[\"$ua\"]"
  [ -n "$cf" ] && h="$h,\"Cf-Connecting-Ip\":[\"$cf\"]"
  printf '{"msg":"handled request","request":{"client_ip":"%s","remote_ip":"%s:5","headers":{%s}}}\n' "$ci" "$ci" "$h"
}

# 1. three requests, one dominant client -> total 3, top 2, ip, share 66
t "dominant-client"
IN=$(printf '%s\n%s\n%s\n' "$(acc 203.0.113.4)" "$(acc 203.0.113.4)" "$(acc 198.51.100.8)")
run "$IN"; a_eq "3 2 203.0.113.4 66 3 0"

# 2. CF-Connecting-IP wins over client_ip (behind Cloudflare: count the real client). Its
#    packets come from Cloudflare, so a drop at the box cannot stop it: exempt.
t "cf-connecting-ip-preferred"
IN=$(printf '%s\n%s\n' "$(acc 104.16.0.1 203.0.113.99)" "$(acc 104.16.0.1 203.0.113.99)")
run "$IN"; a_eq "2 2 203.0.113.99 100 2 1"

# 2b. SECURITY: an address Caddy took from X-Forwarded-For through a trusted proxy (the peer
#     is the proxy) may be one the client wrote. It counts, but it is never blocked, so a
#     flood cannot steer the drop at someone else.
t "proxied-client-ip-exempt"
XFF='{"msg":"handled request","request":{"client_ip":"198.51.100.7","remote_ip":"172.18.0.5:5","headers":{"User-Agent":["curl/8"]}}}'
IN=$(printf '%s\n%s\n' "$XFF" "$XFF")
run "$IN"; a_eq "2 2 198.51.100.7 100 2 1"

# 3. a good-bot UA still counts (a flood can claim to be Googlebot), but a top client whose
#    requests mostly carry one is exempt from a block (Discordbot must never be dropped)
t "good-bot-ua-counted-and-exempt"
BOT='Mozilla/5.0 (compatible; Discordbot/2.0)'
IN=$(printf '%s\n%s\n%s\n' "$(acc 203.0.113.4 '' "$BOT")" "$(acc 203.0.113.4 '' "$BOT")" "$(acc 198.51.100.8)")
run "$IN"; a_eq "3 2 203.0.113.4 66 3 1"

# 3b. a flood that claims to be Googlebot is seen: every request counts
t "fake-googlebot-flood-counted"
BOT='Mozilla/5.0 (compatible; Googlebot/2.1)'
IN=$(printf '%s\n%s\n%s\n' "$(acc 203.0.113.4 '' "$BOT")" "$(acc 203.0.113.4 '' "$BOT")" "$(acc 203.0.113.4 '' "$BOT")")
run "$IN"; a_eq "3 3 203.0.113.4 100 3 1"

# 3c. a client that only sometimes sends a good-bot UA is not exempt
t "mostly-not-bot-not-exempt"
IN=$(printf '%s\n%s\n%s\n' "$(acc 203.0.113.4)" "$(acc 203.0.113.4)" "$(acc 203.0.113.4 '' 'Googlebot/2.1')")
run "$IN"; a_eq "3 3 203.0.113.4 100 3 0"

# 4. a protected CDN client_ip (raw Cloudflare edge IP, no CF header) still counts, and is
#    exempt from a block when it is the top client
t "protected-cdn-counted-and-exempt"
IN=$(printf '%s\n%s\n%s\n' "$(acc 104.16.0.9)" "$(acc 104.16.0.9)" "$(acc 198.51.100.88)")
run "$IN"; a_eq "3 2 104.16.0.9 66 3 1"

# 5. console-format / non-JSON lines: seen but not parsed -> total 0, lines>0
t "console-not-json"
IN=$(printf 'x plain line 1\nplain line 2\n')
run "$IN"; a_eq "0 0 - 0 2 0"

# 6. empty input -> all zero
t "empty"
run ""; a_eq "0 0 - 0 0 0"

# 7. non-access log lines (Caddy info) are seen but not counted
t "non-access-skipped"
IN=$(printf '%s\n%s\n' '{"msg":"served config","logger":"admin.api"}' "$(acc 203.0.113.4)")
run "$IN"; a_eq "1 1 203.0.113.4 100 2 0"

# 8. SECURITY: a spoofed CF-Connecting-IP from a NON-Cloudflare peer is IGNORED, so a
#    direct CDN-bypass flooder cannot forge the header to blame (and get dropped) an
#    innocent third party. remote_ip is the attacker (203.0.113.7, not Cloudflare), so
#    the count sticks to the real peer, not the forged 203.0.113.99.
t "cf-header-spoof-ignored-off-cloudflare"
IN=$(printf '%s\n%s\n' "$(acc 203.0.113.7 203.0.113.99)" "$(acc 203.0.113.7 203.0.113.99)")
run "$IN"; a_eq "2 2 203.0.113.7 100 2 0"

# 9. a line whose resolved IP does not parse is skipped (strict validation) but still
#    counted as seen.
t "unparseable-ip-skipped"
IN=$(printf '%s\n%s\n' "$(acc not-an-ip)" "$(acc 198.51.100.8)")
run "$IN"; a_eq "1 1 198.51.100.8 100 2 0"

# 10. a byte that is not UTF-8 spoils only its own line, even where Python would decode
#     stdin strictly (as under a UTF-8 service locale; an attacker can put raw bytes in a
#     log): the other requests are still counted.
t "non-utf8-line-skipped"
printf '%s\n' "$(acc 203.0.113.4)" > "$WORK_IN"
printf 'raw \377\376 bytes {"msg":"handled request"}\n' >> "$WORK_IN"
printf '%s\n' "$(acc 203.0.113.4)" >> "$WORK_IN"
OUT=$(PYTHONIOENCODING=utf-8:strict "$PY" "$AGG" < "$WORK_IN" 2>/dev/null | tr -d '\r')
a_eq "2 2 203.0.113.4 100 3 0"

# 11. when the script itself cannot run, it prints NOTHING and exits 1, never a made-up
#     "0 0 - 0 0 0" that the detector would read as a quiet window (and use to close a card).
t "failure-prints-nothing"
OUT=$("$PY" "$AGG" <&- 2>/dev/null | tr -d '\r'); RC=$("$PY" "$AGG" <&- >/dev/null 2>&1; echo $?)
a_eq ""
[ "$RC" = 1 ] && ok || bad "expected exit 1 when it cannot run, got $RC"

rm -f "$WORK_IN"
echo ""
echo "flood-http-aggregate: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
