#!/usr/bin/env sh
# nethersec-report.test.sh: offline harness for the report transport. A mock `curl` on
# PATH records its arguments and the config it reads on stdin, and answers with a
# canned status. Asserts each format's request, the data-event skip, the protocol's
# limits, the exit codes, and that the key and the URL never reach curl's arguments.
#
#   sh host/test/nethersec-report.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../nethersec-report.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "nethersec-report.test: python3 is required"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/nrt.$$"); mkdir -p "$WORK"
BIN="$WORK/bin"; mkdir -p "$BIN"
# A key built at runtime, so no fixture looks like a real secret.
KEY=$(printf 'ab%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32)
HUB="https://hub.example.com/v1/report"
DISCORD="https://discord.com/api/webhooks/123456789012345678/$(printf 'x%.0s' 1 2 3 4 5 6 7 8)"
NTFY="https://ntfy.example.com/$(printf 'topic%s' 42)"

cat > "$BIN/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$MOCK_DIR/argv"
cat > "$MOCK_DIR/config"
: > "$MOCK_DIR/called"
if [ "${MOCK_RC:-0}" != 0 ]; then
  echo "curl: (7) Failed to connect to hub.example.com port 443" >&2
  printf '\n%s' "${MOCK_FAIL_CODE:-000}"
  exit "$MOCK_RC"
fi
printf '%s\n%s' "${MOCK_BODY:-}" "${MOCK_CODE:-202}"
exit 0
EOF
chmod +x "$BIN/curl"

PASS=0; FAIL=0; CUR=""
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; rm -f "$WORK/argv" "$WORK/config" "$WORK/called"; }

# send ARGS...: runs the transport with the env set by the case (U, K, F, MOCK_*).
send() {
  OUT=$(env -i PATH="$BIN:$PATH" HOME="$WORK" MOCK_DIR="$WORK" \
    MOCK_RC="${MOCK_RC:-0}" MOCK_CODE="${MOCK_CODE:-202}" MOCK_BODY="${MOCK_BODY:-}" MOCK_FAIL_CODE="${MOCK_FAIL_CODE:-000}" \
    NETHERSEC_REPORT_URL="${U:-}" NETHERSEC_REPORT_KEY="${K:-}" NETHERSEC_REPORT_FORMAT="${F:-}" \
    sh "$SCRIPT" "$@" 2>&1)
  RC=$?
}
reset() { U="$HUB"; K="$KEY"; F=""; MOCK_RC=0; MOCK_CODE=202; MOCK_BODY=""; MOCK_FAIL_CODE=000; }

# cfg_val NAME: the value of the first `NAME = "..."` line of the config, unescaped.
cfg_val() {
  python3 -I - "$WORK/config" "$1" <<'PY'
import sys
name = sys.argv[2]
for line in open(sys.argv[1], encoding="ascii"):
    head = name + ' = "'
    if line.startswith(head) and line.rstrip("\n").endswith('"'):
        raw = line.rstrip("\n")[len(head):-1]
        out, i = [], 0
        while i < len(raw):
            c = raw[i]
            if c == "\\" and i + 1 < len(raw):
                out.append(raw[i + 1]); i += 2
            else:
                out.append(c); i += 1
        sys.stdout.write("".join(out))
        break
PY
}
headers() { cfg_val_all header; }
cfg_val_all() { grep "^$1 = " "$WORK/config" 2>/dev/null | sed "s/^$1 = \"//; s/\"\$//"; }
# body_json EXPR: evaluates a Python expression over the parsed JSON body `b`.
body_json() {
  cfg_val data-raw > "$WORK/body"
  python3 -I - "$WORK/body" "$1" <<'PY'
import json, sys
b = json.load(open(sys.argv[1], encoding="ascii"))
sys.exit(0 if eval(sys.argv[2], {"b": b}) else 1)
PY
}
a_rc()       { [ "$RC" = "$1" ] && ok || bad "expected exit $1, got $RC: $OUT"; }
a_called()   { [ -f "$WORK/called" ] && ok || bad "curl was not called"; }
a_uncalled() { [ -f "$WORK/called" ] && bad "curl must not be called" || ok; }
a_json()     { body_json "$1" && ok || bad "body check failed: $1 (body: $(cat "$WORK/body" 2>/dev/null))"; }
a_hdr()      { headers | grep -qxF -- "$1" && ok || bad "expected header '$1' (got: $(headers | tr '\n' '|'))"; }
a_no_hdr()   { headers | grep -q -- "$1" && bad "header matching '$1' must not be sent" || ok; }
a_out_has()  { printf '%s' "$OUT" | grep -qF -- "$1" && ok || bad "expected output to contain '$1' (got: $OUT)"; }
# The key and the URL are secrets: never in curl's argv, never in what the script prints.
a_secrets_hidden() {
  for s in "$KEY" "$HUB" "$DISCORD" "$NTFY"; do
    grep -qF -- "$s" "$WORK/argv" 2>/dev/null && bad "a secret reached curl's argv: $s"
    printf '%s' "$OUT" | grep -qF -- "$s" && bad "a secret was printed: $s"
  done
  grep -qxF -- "-K" "$WORK/argv" 2>/dev/null && ok || bad "curl must read its config from stdin (-K -)"
}

# 1. hub (the default): the protocol body, the bearer key, 202 -> exit 0.
t "hub-default"; reset
send --kind security --source web1 --event ssh-auth-burst --severity warning --title "SSH login burst" --detail "2300 failed" --group edge
a_rc 0; a_called; a_secrets_hidden
[ "$(cfg_val url)" = "$HUB" ] && ok || bad "the URL must be in the config (got: $(cfg_val url))"
a_hdr "Authorization: Bearer $KEY"; a_hdr "Content-Type: application/json"
a_json 'b == {"v": 1, "kind": "security", "source": "web1", "event": "ssh-auth-burst", "state": "triggered", "severity": "warning", "title": "SSH login burst", "detail": "2300 failed", "group": "edge"}'

# 2. defaults: kind uptime, state triggered, empty severity (the hub applies its default).
t "hub-defaults"; reset
send --source web1 --event backup
a_rc 0; a_json 'b["kind"] == "uptime" and b["state"] == "triggered" and b["severity"] == "" and b["title"] == ""'

# 3. a resolved report.
t "hub-resolved"; reset
send --kind security --source web1 --event ssh-auth-burst --state resolved
a_rc 0; a_json 'b["state"] == "resolved"'

# 4. only a 2xx counts as sent; the log never shows the key or the URL.
t "hub-400"; reset; MOCK_CODE=400; MOCK_BODY='{"error":"detail: too long"}'
send --kind security --source web1 --event x
a_rc 1; a_out_has "HTTP 400"; a_out_has "detail: too long"; a_secrets_hidden
t "hub-503"; reset; MOCK_CODE=503
send --kind security --source web1 --event x; a_rc 1
t "hub-301-is-not-sent"; reset; MOCK_CODE=301
send --kind security --source web1 --event x; a_rc 1
t "hub-204-is-sent"; reset; MOCK_CODE=204
send --kind security --source web1 --event x; a_rc 0
# a 403 (the key may not send this report: a data event from a dm= key) is its own code,
# 4, so a caller can tell it from an answer that may change on the next run
t "hub-403-is-exit-4"; reset; MOCK_CODE=403; MOCK_BODY='{"error":"this key cannot send data events"}'
send --kind security --source web1 --event reboot-pending --severity info --detail "v=1"
a_rc 4; a_out_has "HTTP 403"; a_out_has "cannot send data events"; a_secrets_hidden
t "hub-401-is-still-exit-1"; reset; MOCK_CODE=401
send --kind security --source web1 --event x; a_rc 1
t "hub-403-after-curl-error-is-exit-4"; reset; MOCK_RC=28; MOCK_FAIL_CODE=403
send --kind security --source web1 --event x; a_rc 4
# no answer at all (no HTTP status) is exit 3, so a caller can stop posting for the run
t "curl-fails"; reset; MOCK_RC=7
send --kind security --source web1 --event x
a_rc 3; a_out_has "curl exit 7"; a_secrets_hidden
# curl failed after the hub answered (a timeout mid-body): not sent, but not "no answer"
t "curl-fails-after-answer"; reset; MOCK_RC=28; MOCK_FAIL_CODE=202
send --kind security --source web1 --event x; a_rc 1

# 5. the hub format needs a key; without one nothing is sent.
t "hub-needs-key"; reset; K=""
send --kind security --source web1 --event x
a_rc 2; a_uncalled; a_out_has "NETHERSEC_REPORT_KEY"
t "url-required"; reset; U=""
send --kind security --source web1 --event x; a_rc 2; a_uncalled

# 6. bad arguments are refused before anything is sent.
t "bad-kind"; reset; send --kind sec --source web1 --event x; a_rc 2; a_uncalled
t "bad-source"; reset; send --source Web1 --event x; a_rc 2; a_uncalled
t "bad-source-long"; reset; send --source "$(printf 'a%.0s' $(seq 1 41))" --event x; a_rc 2
t "bad-event"; reset; send --source web1 --event "has space"; a_rc 2; a_uncalled
t "bad-state"; reset; send --source web1 --event x --state open; a_rc 2
t "bad-severity"; reset; send --source web1 --event x --severity high; a_rc 2
t "bad-format"; reset; F=slack; send --source web1 --event x; a_rc 2; a_uncalled
t "missing-value"; reset; send --source web1 --event; a_rc 2
t "unknown-flag"; reset; send --source web1 --event x --page; a_rc 2

# 7. text is cut to the protocol's limits and cleaned to printable ASCII, and quotes,
#    backslashes and newlines still make valid JSON.
t "limits-and-escaping"; reset
LONG=$(printf 'x%.0s' $(seq 1 1600)); TLONG=$(printf 't%.0s' $(seq 1 130)); GLONG=$(printf 'g%.0s' $(seq 1 50))
send --kind security --source web1 --event x --title "$TLONG" --detail "$LONG" --group "$GLONG"
a_rc 0; a_json 'len(b["title"]) == 120 and len(b["detail"]) == 1500 and len(b["group"]) == 40'
t "escaping"; reset
NL='
'
send --kind security --source web1 --event x --title 'say "hi" \ there' --detail "line1${NL}line2$(printf '\t')tab$(printf '\001')ctl"
a_rc 0; a_json 'b["title"] == "say \"hi\" \\ there" and b["detail"] == "line1 line2 tabctl"'

# 8. the data events: the full 64000 characters for the hub.
t "hub-data-event"; reset
BIG=$(printf 'p%.0s' $(seq 1 3000))
send --kind security --source web1 --event container-packages --severity info --detail "v=1 ctr=web pkgs=$BIG"
a_rc 0; a_json 'b["event"] == "container-packages" and len(b["detail"]) > 3000'

# 9. Discord: picked from the URL, plain text, nothing can ping, no key sent.
t "discord-auto"; reset; U="$DISCORD"
send --kind security --source web1 --event ssh-auth-burst --severity critical --title "SSH login burst" --detail "@everyone 2300 failed"
a_rc 0; a_called; a_secrets_hidden; a_no_hdr "Authorization"
a_json 'b["allowed_mentions"] == {"parse": []} and b["content"] == "CRITICAL web1 ssh-auth-burst: SSH login burst\n@everyone 2300 failed"'
t "discord-default-severity"; reset; U="$DISCORD"
send --kind security --source web1 --event x
a_json 'b["content"].startswith("WARNING web1 x")'
send --source web1 --event backup
a_json 'b["content"].startswith("CRITICAL web1 backup")'
t "discord-resolved"; reset; U="$DISCORD"
send --kind security --source web1 --event x --state resolved --title "Thing" --detail "ignored"
a_json 'b["content"].startswith("RESOLVED") and "check it yourself" in b["content"] and "ignored" not in b["content"]'
t "discord-explicit"; reset; U="https://chat.example.com/hook"; F=discord; K=""
send --kind security --source web1 --event x; a_rc 0; a_json '"content" in b'
t "discord-limit"; reset; U="$DISCORD"
send --kind security --source web1 --event x --title "$TLONG" --detail "$LONG"
a_json 'len(b["content"]) <= 2000'

# 10. ntfy: a text body with Title and Priority headers; the key only as a bearer.
t "ntfy-critical"; reset; U="$NTFY"; F=ntfy
send --kind security --source web1 --event ssh-auth-burst --severity critical --title "SSH login burst" --detail "2300 failed"
a_rc 0; a_secrets_hidden
a_hdr "Content-Type: text/plain"; a_hdr "Title: web1: SSH login burst"; a_hdr "Priority: 5"; a_hdr "Authorization: Bearer $KEY"
[ "$(cfg_val data-raw)" = "2300 failed" ] && ok || bad "ntfy body (got: $(cfg_val data-raw))"
t "ntfy-warning-no-key"; reset; U="$NTFY"; F=ntfy; K=""
send --kind security --source web1 --event x --severity warning
a_rc 0; a_hdr "Priority: 3"; a_no_hdr "Authorization"
t "ntfy-info-resolved"; reset; U="$NTFY"; F=ntfy
send --kind security --source web1 --event x --severity info; a_hdr "Priority: 2"
send --kind security --source web1 --event x --state resolved --title "Thing"
a_hdr "Priority: 2"; a_hdr "Title: Resolved: web1 x"

# 11. json: the hub body, the bearer only when a key is set.
t "json-with-key"; reset; F=json
send --kind security --source web1 --event x --detail d
a_rc 0; a_hdr "Authorization: Bearer $KEY"; a_json 'b["v"] == 1 and b["detail"] == "d"'
t "json-without-key"; reset; F=json; K=""
send --kind security --source web1 --event x; a_rc 0; a_no_hdr "Authorization"

# 12. data events are skipped in every format but the hub, with a log line and exit 0.
for fmt in discord ntfy json; do
  for ev in reboot-pending container-packages; do
    t "skip-$fmt-$ev"; reset; F="$fmt"; [ "$fmt" = discord ] && U="$DISCORD"
    send --kind security --source web1 --event "$ev" --severity info --detail "v=1"
    a_rc 0; a_uncalled; a_out_has "skipped data event $ev"
  done
done
# ...but an uptime report that happens to share the name is not a data event.
t "uptime-not-data"; reset; F=json
send --kind uptime --source web1 --event reboot-pending; a_rc 0; a_called

# 13. the REAL curl against a server on 127.0.0.1: proves curl parses the stdin config
#     (quotes, backslashes, a 64,000-character data event) into the exact request.
#     Skipped where curl is not installed.
REAL_CURL=$(command -v curl 2>/dev/null || :)
if [ -z "$REAL_CURL" ]; then
  echo "  (skipped real-curl: curl is not installed)"
else
  t "real-curl"
  cat > "$WORK/server.py" <<'PY'
import http.server, json, sys
out = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        with open(out, "w", encoding="ascii") as f:
            json.dump({"path": self.path, "auth": self.headers.get("Authorization"),
                       "ctype": self.headers.get("Content-Type"), "body": body.decode("ascii")}, f)
        code = 202 if self.path == "/v1/report" else 403 if self.path == "/forbidden" else 400
        self.send_response(code); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *a):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[2], "w").write(str(s.server_port))
s.handle_request()
PY
  real_send() {  # url-path ARGS... -> one request to a fresh one-shot server
  rm -f "$WORK/got.json" "$WORK/port"
  python3 -I "$WORK/server.py" "$WORK/got.json" "$WORK/port" &
  srv=$!
  i=0; while [ ! -s "$WORK/port" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  p1="$1"; shift
  OUT=$(env -i PATH="$PATH" NETHERSEC_REPORT_URL="http://127.0.0.1:$(cat "$WORK/port")$p1" NETHERSEC_REPORT_KEY="$KEY" \
    sh "$SCRIPT" "$@" 2>&1)
  RC=$?
  wait "$srv" 2>/dev/null
  }
  BIGD="v=1 ctr=web pkgs=$(printf 'a@1,%.0s' $(seq 1 16000))"
  real_send /v1/report --kind security --source web1 --event container-packages --severity info --title 'q"uote \ back' --detail "$BIGD"
  a_rc 0
  python3 -I - "$WORK/got.json" "$KEY" <<'PY' && ok || bad "the server did not get the exact request: $(head -c 300 "$WORK/got.json" 2>/dev/null)"
import json, sys
g = json.load(open(sys.argv[1], encoding="ascii"))
b = json.loads(g["body"])
assert g["auth"] == "Bearer " + sys.argv[2], g["auth"]
assert g["ctype"] == "application/json", g["ctype"]
assert b["title"] == 'q"uote \\ back', b["title"]
assert len(b["detail"]) == 64000 and b["detail"].startswith("v=1 ctr=web pkgs=a@1,"), len(b["detail"])
PY
  real_send /wrong --kind security --source web1 --event x
  a_rc 1; a_out_has "HTTP 400"; printf "%s" "$OUT" | grep -qF "127.0.0.1" && bad "the URL was printed" || ok
  printf "%s" "$OUT" | grep -qF -- "$KEY" && bad "the key was printed" || ok
  # a real 403 from the server is exit 4
  real_send /forbidden --kind security --source web1 --event reboot-pending --severity info --detail "v=1"
  a_rc 4; a_out_has "HTTP 403"
  # nothing listening: the real curl gets no HTTP status, so exit 3
  t "real-curl-no-answer"
  OUT=$(env -i PATH="$PATH" NETHERSEC_REPORT_URL="http://127.0.0.1:1/v1/report" NETHERSEC_REPORT_KEY="$KEY" \
    sh "$SCRIPT" --kind security --source web1 --event x 2>&1)
  RC=$?
  a_rc 3; a_out_has "HTTP 000"; printf "%s" "$OUT" | grep -qF -- "$KEY" && bad "the key was printed" || ok
fi

echo ""
echo "nethersec-report: $PASS passed, $FAIL failed"
rm -rf "$WORK" 2>/dev/null || :
[ "$FAIL" -eq 0 ]
