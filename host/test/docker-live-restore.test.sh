#!/usr/bin/env sh
# docker-live-restore.test.sh: offline harness for docker-live-restore.sh. Mocks the
# docker client, dockerd --validate and systemctl through the script's env seams, and
# points it at a scratch daemon.json, so it needs no Docker, no root and no network.
# Asserts:
#   - no Docker: nothing written, exit 0 (2 with --check)
#   - --check reports on/off without writing
#   - already on: no write, no reload
#   - off: merges "live-restore": true keeping every other key, backs up the old file,
#     reloads once, and confirms the daemon reports it
#   - a daemon.json that is not a JSON object, or that dockerd rejects, is left as it was
#     and nothing is reloaded
#   - a swarm node is refused
#   - a reload that does not take is an error, not a silent success
#
#   sh host/test/docker-live-restore.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../docker-live-restore.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }
command -v bash >/dev/null 2>&1 || { echo "docker-live-restore.test: bash is required"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "docker-live-restore.test: python3 is required"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dlr.$$"); mkdir -p "$WORK"
BIN="$WORK/bin"; mkdir -p "$BIN"
CONF_DIR="$WORK/etc-docker"; CONF="$CONF_DIR/daemon.json"

# docker: `info -f {{.LiveRestoreEnabled}}` prints $WORK/lr (true|false); a `fail` file
# makes every call fail like a stopped daemon. Swarm state comes from $WORK/swarm.
cat > "$BIN/docker" <<'EOF'
#!/bin/sh
[ -f "$MOCK_DIR/fail" ] && exit 1
case "$*" in
  *LiveRestoreEnabled*) cat "$MOCK_DIR/lr" ;;
  *LocalNodeState*) cat "$MOCK_DIR/swarm" ;;
  *) exit 1 ;;
esac
EOF
# dockerd --validate: valid JSON passes unless $WORK/reject exists.
cat > "$BIN/dockerd" <<'EOF'
#!/bin/sh
[ -f "$MOCK_DIR/reject" ] && { echo "unable to configure the Docker daemon: bad key"; exit 1; }
f=""; while [ $# -gt 0 ]; do [ "$1" = "--config-file" ] && f="$2"; shift; done
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$f"
EOF
# systemctl reload docker: logged; the daemon picks up the file unless $WORK/noeffect.
cat > "$BIN/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$MOCK_DIR/systemctl.log"
if [ "$*" = "reload docker" ] && [ ! -f "$MOCK_DIR/noeffect" ]; then
  python3 -c 'import json,sys; print("true" if json.load(open(sys.argv[1])).get("live-restore") is True else "false")' "$MOCK_CONF" > "$MOCK_DIR/lr"
fi
exit 0
EOF
chmod +x "$BIN/docker" "$BIN/dockerd" "$BIN/systemctl"

PASS=0; FAIL=0; CUR=""
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; }

setup() {
  rm -rf "$CONF_DIR"; mkdir -p "$CONF_DIR"
  rm -f "$WORK/fail" "$WORK/reject" "$WORK/noeffect" "$WORK/systemctl.log"
  echo false > "$WORK/lr"; echo inactive > "$WORK/swarm"
  DOCKER_CMD="$BIN/docker"
}
runit() {
  OUT=$(env HOSTSEC_DOCKER_CMD="$DOCKER_CMD" HOSTSEC_DOCKERD_CMD="$BIN/dockerd" \
    HOSTSEC_SYSTEMCTL_CMD="$BIN/systemctl" HOSTSEC_DOCKER_DAEMON_JSON="$CONF" \
    HOSTSEC_LR_WAIT_SECS=1 MOCK_DIR="$WORK" MOCK_CONF="$CONF" \
    bash "$SCRIPT" "$@" 2>&1)
  RC=$?
}
a_rc()       { [ "$RC" = "$1" ] && ok || bad "expected exit $1, got $RC: $OUT"; }
a_has()      { printf '%s' "$OUT" | grep -qF -- "$1" && ok || bad "expected output to contain '$1' (got: $OUT)"; }
a_reloads()  { n=$(grep -c '^reload docker$' "$WORK/systemctl.log" 2>/dev/null); n=${n:-0}; [ "$n" = "$1" ] && ok || bad "expected $1 reload(s), got $n"; }
a_conf_key() { python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); sys.exit(0 if json.dumps(c.get(sys.argv[2])) == sys.argv[3] else 1)' "$CONF" "$1" "$2" 2>/dev/null \
                 && ok || bad "expected $1=$2 in daemon.json (got: $(cat "$CONF" 2>/dev/null))"; }
a_conf_is()  { [ "$(cat "$CONF" 2>/dev/null)" = "$1" ] && ok || bad "daemon.json must be unchanged (got: $(cat "$CONF" 2>/dev/null))"; }
a_no_conf()  { [ -e "$CONF" ] && bad "daemon.json must not be written (got: $(cat "$CONF"))" || ok; }
a_baks()     { n=$(ls "$CONF_DIR" | grep -c '\.bak\.' ); [ "$n" = "$1" ] && ok || bad "expected $1 backup(s), got $n: $(ls "$CONF_DIR")"; }
a_no_tmp()   { ls "$CONF_DIR" | grep -q '\.tmp\.' && bad "a temp file was left behind: $(ls "$CONF_DIR")" || ok; }

# 1. no Docker on the box: nothing to do, nothing written; --check says so with exit 2
t "no-docker"
setup; DOCKER_CMD="$WORK/no-such-docker"
runit; a_rc 0; a_has "not installed"; a_no_conf; a_reloads 0
runit --check; a_rc 2

# 2. --check never writes: off is exit 1, on is exit 0, a dead daemon is exit 1
t "check-only"
setup; runit --check; a_rc 1; a_has "OFF"; a_no_conf; a_reloads 0
echo true > "$WORK/lr"; runit --check; a_rc 0; a_has "is on"
: > "$WORK/fail"; runit --check; a_rc 1; a_has "cannot read"

# 3. already on: no write, no reload
t "already-on"
setup; echo true > "$WORK/lr"
runit; a_rc 0; a_no_conf; a_reloads 0

# 4. off with no daemon.json: writes just the key, reloads once, confirms
t "fresh-file"
setup
runit; a_rc 0; a_conf_key live-restore true; a_reloads 1; a_baks 0; a_no_tmp
a_has "Running containers were not restarted"
# a second run is a no-op
runit; a_rc 0; a_reloads 1

# 5. existing keys survive, the old file is backed up byte for byte
t "merge-keeps-keys"
setup
printf '{\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "10m", "max-file": "5" }\n}\n' > "$CONF"
cp "$CONF" "$WORK/orig.json"
runit; a_rc 0
a_conf_key live-restore true; a_conf_key log-driver '"json-file"'
a_conf_key log-opts '{"max-size": "10m", "max-file": "5"}'
a_baks 1
cmp -s "$WORK/orig.json" "$CONF_DIR"/daemon.json.bak.* && ok || bad "the backup must match the old file"

# 6. live-restore explicitly false in the file is flipped, not duplicated
t "explicit-false"
setup; printf '{"live-restore": false}\n' > "$CONF"
runit; a_rc 0; a_conf_key live-restore true
[ "$(grep -c 'live-restore' "$CONF")" = 1 ] && ok || bad "live-restore must appear once (got: $(cat "$CONF"))"

# 7. a file that is not a JSON object is left alone, nothing reloads
t "invalid-json-untouched"
setup; printf '{ "log-driver": "json-file", }\n' > "$CONF"; before=$(cat "$CONF")
runit; a_rc 1; a_has "not valid JSON"; a_conf_is "$before"; a_reloads 0; a_no_tmp; a_baks 0
setup; printf '["live-restore"]\n' > "$CONF"; before=$(cat "$CONF")
runit; a_rc 1; a_has "not a JSON object"; a_conf_is "$before"; a_reloads 0

# 8. dockerd rejects the merged file: the old one stays, nothing reloads
t "validate-rejects"
setup; printf '{"bogus-key": 1}\n' > "$CONF"; before=$(cat "$CONF"); : > "$WORK/reject"
runit; a_rc 1; a_has "rejected"; a_conf_is "$before"; a_reloads 0; a_no_tmp; a_baks 0

# 9. a swarm node is refused before anything is written
t "swarm-refused"
setup; echo active > "$WORK/swarm"
runit; a_rc 1; a_has "swarm"; a_no_conf; a_reloads 0

# 10. the reload did not take: an error, never a silent success
t "reload-no-effect"
setup; : > "$WORK/noeffect"
runit; a_rc 1; a_has "still reports"; a_conf_key live-restore true; a_reloads 1

# 11. a dead daemon: nothing written
t "daemon-down"
setup; : > "$WORK/fail"
runit; a_rc 1; a_has "cannot read"; a_no_conf; a_reloads 0

bash -n "$SCRIPT" && ok || bad "docker-live-restore.sh has a bash syntax error"

echo ""
echo "docker-live-restore: $PASS passed, $FAIL failed"
rm -rf "$WORK" 2>/dev/null || :
[ "$FAIL" -eq 0 ]
