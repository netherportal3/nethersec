#!/usr/bin/env sh
# install.test.sh: offline harness for install.sh. Every run points NETHERSEC_ROOT at a
# scratch directory, so /opt, /etc and /var/lib live under it, and mocks systemctl,
# journalctl, apt-get, apt-mark and python3 on PATH. Covers the path refusal
# (--check-path), the copy into /opt/nethersec, report.env (never clobbered, mode 600),
# --new-key and --key-stdin, the Discord-URL guard, the applier and flood parts, an
# update from a newer clone, and --uninstall (holds released first) and --purge.
#
#   sh host/test/install.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
INSTALL="$HERE/../install.sh"
[ -f "$INSTALL" ] || { echo "cannot find $INSTALL"; exit 2; }
command -v bash >/dev/null 2>&1 || { echo "install.test: bash is required"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/ist.$$"); mkdir -p "$WORK"
chmod 0755 "$WORK"
# The check walks up to /, so a world-writable non-sticky directory above $WORK
# would fail every case here. Say so once instead.
d="$WORK"
while [ "$d" != "/" ]; do
  d=$(dirname -- "$d")
  if [ -n "$(find "$d" -maxdepth 0 -type d -perm -0002 ! -perm -1000 2>/dev/null)" ]; then
    echo "install.test: $d is world-writable without the sticky bit; set TMPDIR to a safe directory"
    rm -rf "$WORK"; exit 2
  fi
done

BIN="$WORK/bin"; mkdir -p "$BIN"
R="$WORK/root"
LOG="$WORK/calls.log"
HUB="https://hub.example.com/v1/report"
DISCORD="https://discord.com/api/webhooks/123456789012345678/$(printf 'z%.0s' 1 2 3 4 5 6)"
KEY=$(printf 'ef%.0s' $(seq 1 32))

for c in systemctl journalctl apt-get; do
  printf '#!/bin/sh\necho "%s $*" >> "%s"\nexit 0\n' "$c" "$LOG" > "$BIN/$c"
done
# apt-mark: unhold drops a name from the fake hold list; showhold prints what is left.
cat > "$BIN/apt-mark" <<EOF
#!/bin/sh
echo "apt-mark \$*" >> "$LOG"
case "\$1" in
  unhold) [ -f "$WORK/sticky-hold" ] && exit 1
          grep -vx "\$2" "$WORK/holds" > "$WORK/holds.t" 2>/dev/null; mv "$WORK/holds.t" "$WORK/holds" ;;
  showhold) cat "$WORK/holds" 2>/dev/null ;;
esac
exit 0
EOF
# python3: no python3-apt here, so install.sh tries to install it.
cat > "$BIN/python3" <<'EOF'
#!/bin/sh
case "$*" in *"import apt"*) exit 1 ;; esac
exit 0
EOF
chmod +x "$BIN"/*

PASS=0; FAIL=0; CUR=""
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; : > "$LOG"; }
fresh() { rm -rf "$R"; mkdir -p "$R"; chmod 0755 "$R"; rm -f "$WORK/holds" "$WORK/sticky-hold"; }
# runit [ARGS...]: install.sh from this repo; STDIN_TEXT feeds its stdin.
runit() {
  OUT=$(printf '%s' "${STDIN_TEXT:-}" | env PATH="$BIN:$PATH" NETHERSEC_ROOT="$R" bash "${SRC:-$INSTALL}" "$@" 2>&1)
  RC=$?; STDIN_TEXT=""
}
ENV="$R/etc/nethersec/report.env"
envval() { grep -E "^$1=" "$ENV" 2>/dev/null | tail -n 1 | sed 's/^[^=]*=//'; }
mode() { stat -c %a "$1" 2>/dev/null; }
a_rc()     { [ "$RC" = "$1" ] && ok || bad "expected exit $1, got $RC: $OUT"; }
a_has()    { printf '%s' "$OUT" | grep -qF -- "$1" && ok || bad "expected output to contain '$1' (got: $OUT)"; }
a_lacks()  { printf '%s' "$OUT" | grep -qF -- "$1" && bad "output must NOT contain '$1' (got: $OUT)" || ok; }
a_file()   { [ -f "$1" ] && ok || bad "expected file $1"; }
a_nofile() { [ -e "$1" ] && bad "expected $1 to be gone" || ok; }
a_mode()   { [ "$(mode "$1")" = "$2" ] && ok || bad "expected mode $2 on $1, got $(mode "$1")"; }
a_call()   { grep -qF -- "$1" "$LOG" 2>/dev/null && ok || bad "expected a call '$1' (got: $(tr '\n' '|' < "$LOG"))"; }
a_nocall() { grep -qF -- "$1" "$LOG" 2>/dev/null && bad "unexpected call '$1'" || ok; }

# --- the path check ----------------------------------------------------------------
# 1. a clean path passes, and --check-path writes nothing.
t "check-path-clean"
fresh; runit --check-path; a_rc 0; a_has "path ok"; a_nofile "$R/opt"
# 2. a world-writable directory on the way to /opt/nethersec is refused and named.
t "check-path-dir-777"
fresh; mkdir -p "$R/opt"; chmod 0777 "$R/opt"; runit --check-path
a_rc 1; a_has "refusing"; a_has "  $R/opt"; a_has "sudo chmod o-w $R/opt"; a_lacks "path ok"
# 3. a sticky world-writable directory (like /tmp) is fine.
t "check-path-sticky"
fresh; mkdir -p "$R/opt"; chmod 1777 "$R/opt"; runit --check-path; a_rc 0
# 4. a world-writable script in /opt/nethersec is refused; several land on one fix line.
t "check-path-script-666"
fresh; mkdir -p "$R/opt/nethersec"; : > "$R/opt/nethersec/security-report.sh"; : > "$R/opt/nethersec/cve-severity.py"
chmod 0666 "$R/opt/nethersec/security-report.sh"; chmod 0646 "$R/opt/nethersec/cve-severity.py"
runit --check-path; a_rc 1; a_has "sudo chmod o-w $R/opt/nethersec/security-report.sh $R/opt/nethersec/cve-severity.py"
# 5. an install over a bad path is refused before anything is written.
t "install-refuses-bad-path"
fresh; mkdir -p "$R/opt"; chmod 0777 "$R/opt"; runit --source web1 --report-url "$HUB" --new-key
a_rc 1; a_has "refusing"; a_nofile "$R/opt/nethersec"; a_nofile "$ENV"

# --- a first install ------------------------------------------------------------------
# 6. --new-key: scripts copied root-style, report.env mode 600, the key never printed,
#    only the keys-file line with the key's hash.
t "install-new-key"
fresh; runit --source web1 --report-url "$HUB" --new-key
a_rc 0
a_file "$R/opt/nethersec/security-report.sh"; a_file "$R/opt/nethersec/nethersec-report.sh"
a_file "$R/opt/nethersec/nethersec-status.sh"; a_file "$R/opt/nethersec/cve-severity.py"; a_file "$R/opt/nethersec/VERSION"
a_mode "$R/opt/nethersec" 755; a_mode "$R/opt/nethersec/security-report.sh" 755; a_mode "$R/opt/nethersec/cve-severity.py" 644
[ -d "$R/opt/nethersec/test" ] && bad "the test folder must not be installed" || ok
a_mode "$ENV" 600; a_mode "$R/etc/nethersec" 755; a_mode "$R/var/lib/nethersec" 700
k=$(envval NETHERSEC_REPORT_KEY)
printf '%s' "$k" | grep -Eq '^[0-9a-f]{64}$' && ok || bad "expected a 64-hex key in report.env (got '$k')"
[ "$(envval NETHERSEC_REPORT_URL)" = "$HUB" ] && ok || bad "URL not set"
[ "$(envval HOSTSEC_SOURCE)" = web1 ] && ok || bad "source not set"
a_lacks "$k"
h=$(printf '%s' "$k" | sha256sum | cut -d' ' -f1)
[ "$(printf '%s\n' "$OUT" | tail -n 1)" = "web1 $h page" ] && ok || bad "last line must be 'web1 <sha256> page' (got: $(printf '%s\n' "$OUT" | tail -n 1))"
# it says that reports refused before the hub has the line are sent again, and how to send now
a_has "each run sends them"; a_has "sudo systemctl start nethersec-security-report.service"
a_file "$R/etc/systemd/system/nethersec-security-report.service"; a_file "$R/etc/systemd/system/nethersec-security-report.timer"
grep -q '^ExecStart=/bin/sh /opt/nethersec/security-report.sh$' "$R/etc/systemd/system/nethersec-security-report.service" && ok || bad "the unit must run the /opt/nethersec copy"
a_call "systemctl daemon-reload"; a_call "systemctl enable --now nethersec-security-report.timer"
a_nocall "nethersec-apply-aged"; a_nocall "nethersec-flood-report"
a_lacks "no key yet"; a_lacks "no report URL"

# 7. a second --new-key is refused and changes nothing; --replace-key replaces it.
t "new-key-refuses-existing"
cp "$ENV" "$WORK/env.before"
runit --new-key; a_rc 1; a_has "already has a key"
cmp -s "$ENV" "$WORK/env.before" && ok || bad "report.env must be unchanged after a refusal"
t "new-key-replace"
runit --new-key --replace-key; a_rc 0; a_has "REPLACED the key"
[ "$(envval NETHERSEC_REPORT_KEY)" != "$k" ] && ok || bad "the key must change"
[ "$(grep -c '^NETHERSEC_REPORT_KEY=' "$ENV")" = 1 ] && ok || bad "exactly one key line"

# 8. a re-run keeps every other line of report.env, and says what it changed.
t "rerun-keeps-env"
echo "HOSTSEC_SSH_BURST=900" >> "$ENV"
runit --report-url "https://hub2.example.com/v1/report"
a_rc 0; a_has "CHANGED NETHERSEC_REPORT_URL"; a_lacks "hub2.example.com"
[ "$(envval HOSTSEC_SSH_BURST)" = 900 ] && ok || bad "a tuned value was lost"
[ "$(envval HOSTSEC_SOURCE)" = web1 ] && ok || bad "the source was lost"
a_mode "$ENV" 600

# 9. --key-stdin: a hub key must be 64 hex; a good one is written, never printed.
t "key-stdin"
fresh; STDIN_TEXT="not-hex"; runit --source db1 --report-url "$HUB" --key-stdin
a_rc 1; a_has "64 lowercase hex"; a_nofile "$ENV"
STDIN_TEXT="$KEY
"; runit --source db1 --report-url "$HUB" --key-stdin
a_rc 0; [ "$(envval NETHERSEC_REPORT_KEY)" = "$KEY" ] && ok || bad "the key from stdin was not written"
a_lacks "$KEY"; a_lacks " page"
STDIN_TEXT="$KEY"; runit --key-stdin; a_rc 1; a_has "already has a key"

# 10. no key and no URL: installed, with a warning for each.
t "warn-missing"
fresh; runit --source web1; a_rc 0; a_has "no report URL yet"; a_has "no key yet"

# 11. a Discord webhook URL is a secret: refused on argv, taken from stdin, no key needed.
t "discord-url"
fresh; runit --source web1 --report-url "$DISCORD"
a_rc 1; a_has "--url-stdin"; a_nofile "$ENV"; a_lacks "$DISCORD"
STDIN_TEXT="$DISCORD
"; runit --source web1 --url-stdin
a_rc 0; [ "$(envval NETHERSEC_REPORT_URL)" = "$DISCORD" ] && ok || bad "the stdin URL was not written"
a_lacks "$DISCORD"; a_lacks "no key yet"
runit --new-key; a_rc 1; a_has "makes a hub key"

# 12. --url-stdin and --key-stdin together: URL first, then the key (an ntfy token).
t "url-and-key-stdin"
fresh; STDIN_TEXT="https://ntfy.example.com/private-topic
tk_$(printf 'q%.0s' 1 2 3 4 5 6 7 8)
"; runit --source web1 --format ntfy --url-stdin --key-stdin
a_rc 0; [ "$(envval NETHERSEC_REPORT_FORMAT)" = ntfy ] && ok || bad "format not set"
[ "$(envval NETHERSEC_REPORT_KEY)" = "tk_qqqqqqqq" ] && ok || bad "ntfy token not written (got '$(envval NETHERSEC_REPORT_KEY)')"
a_lacks "private-topic"

# 13. bad flags are refused before anything is written.
t "bad-flags"
fresh
runit --source Web1; a_rc 1; a_nofile "$R/opt/nethersec"
runit --format slack; a_rc 1
runit --new-key --key-stdin --source web1; a_rc 1
runit --purge; a_rc 1; a_has "goes with --uninstall"
runit --report-url ftp://x.example.com; a_rc 1
runit --source; [ "$RC" = 2 ] && ok || bad "a flag without its value must exit 2 (got $RC)"
runit --bogus; [ "$RC" = 2 ] && ok || bad "an unknown flag must exit 2 (got $RC)"
a_nofile "$R/opt/nethersec"
if [ "$(id -u)" -ne 0 ]; then
  OUT=$(env PATH="$BIN:$PATH" bash "$INSTALL" --source web1 2>&1); RC=$?
  a_rc 1; a_has "run as root"
fi

# --- the applier and the flood detector -----------------------------------------------
# 14. --with-applier: python3-apt installed, apply.env from the template (DRY-RUN), the
#     units, and the unattended-upgrades drop-in, followed by a daemon-reload.
t "with-applier"
fresh; runit --source web1 --report-url "$HUB" --new-key --with-applier
a_rc 0
a_call "apt-get install -y python3-apt"
a_file "$R/etc/nethersec/apply.env"; a_mode "$R/etc/nethersec/apply.env" 600
grep -q '^HOSTSEC_APPLY_DRYRUN=1$' "$R/etc/nethersec/apply.env" && ok || bad "apply.env must ship DRY-RUN"
a_file "$R/etc/systemd/system/nethersec-apply-aged.service"; a_file "$R/etc/systemd/system/nethersec-apply-aged.timer"
DROPIN="$R/etc/systemd/system/apt-daily-upgrade.service.d/nethersec-apply-aged.conf"
a_file "$DROPIN"; cmp -s "$DROPIN" "$HERE/../apt-daily-upgrade.nethersec.conf" && ok || bad "the drop-in must be installed verbatim"
a_call "systemctl enable --now nethersec-apply-aged.timer"
awk '/daemon-reload/ { r = NR } /enable --now nethersec-apply-aged.timer/ { e = NR } END { exit !(r && e && r < e) }' "$LOG" \
  && ok || bad "a daemon-reload must come before the timers are enabled"
a_has "DRY-RUN"
# an existing apply.env is never replaced.
echo "HOSTSEC_APPLY_DRYRUN=0" > "$R/etc/nethersec/apply.env"
runit --with-applier; a_rc 0
grep -q '^HOSTSEC_APPLY_DRYRUN=0$' "$R/etc/nethersec/apply.env" && ok || bad "an existing apply.env was overwritten"

# 15. --with-flood: flood.env and the units.
t "with-flood"
runit --with-flood; a_rc 0
a_file "$R/etc/nethersec/flood.env"; a_mode "$R/etc/nethersec/flood.env" 600
a_file "$R/etc/systemd/system/nethersec-flood-report.service"
a_call "systemctl enable --now nethersec-flood-report.timer"
# and a plain re-run refreshes every part already installed.
t "rerun-refreshes-all-parts"
runit; a_rc 0
a_call "enable --now nethersec-security-report.timer"; a_call "enable --now nethersec-apply-aged.timer"; a_call "enable --now nethersec-flood-report.timer"

# 16. --run-now starts each installed part once.
t "run-now"
runit --run-now; a_rc 0
a_call "systemctl start nethersec-security-report.service"; a_call "systemctl start nethersec-apply-aged.service"
a_call "journalctl -u nethersec-flood-report.service"

# --- an update from a newer clone -----------------------------------------------------
# 17. the new copy replaces the old one whole: changed files update, a removed file goes.
t "update-from-newer-clone"
CLONE="$WORK/clone/host"; rm -rf "$WORK/clone"; mkdir -p "$WORK/clone"; cp -R "$HERE/.." "$CLONE"
rm -rf "$CLONE/test"
echo "# newer" >> "$CLONE/security-report.sh"
: > "$R/opt/nethersec/stale-old-file.sh"
SRC="$CLONE/install.sh"; runit; SRC=""; a_rc 0; a_has "updated /opt/nethersec"
tail -n 1 "$R/opt/nethersec/security-report.sh" | grep -q '^# newer$' && ok || bad "the script was not updated"
a_nofile "$R/opt/nethersec/stale-old-file.sh"
ls -d "$R/opt/nethersec".* >/dev/null 2>&1 && bad "a staging dir was left behind" || ok

# --- uninstall --------------------------------------------------------------------------
# 18. --uninstall releases the applier's holds FIRST, then removes the units, the drop-in
#     and /opt/nethersec, and keeps /etc/nethersec.
t "uninstall"
printf 'libfoo\t1.0\tgated\t1\nlibbar\t2.0\tgated\t1\n' > "$R/var/lib/nethersec/holds.apply.tsv"
printf 'libbar\nlibfoo\nadminpin\n' > "$WORK/holds"
runit --uninstall
a_rc 0
a_call "apt-mark unhold libfoo"; a_call "apt-mark unhold libbar"; a_nocall "apt-mark unhold adminpin"
a_has "holds released"
a_call "systemctl disable --now nethersec-security-report.timer"; a_call "systemctl disable --now nethersec-apply-aged.timer"
a_nofile "$R/etc/systemd/system/nethersec-security-report.service"; a_nofile "$R/etc/systemd/system/nethersec-flood-report.timer"
a_nofile "$DROPIN"; a_nofile "$R/opt/nethersec"
a_file "$ENV"; a_has "kept /etc/nethersec"
awk '/apt-mark unhold/ { u = NR } /disable --now/ { if (!d) d = NR } END { exit !(u && d && u < d) }' "$LOG" \
  && ok || bad "the holds must be released before anything is removed"

# 19. a hold that will not come off stops the uninstall with nothing removed.
t "uninstall-sticky-hold"
fresh; runit --source web1 --report-url "$HUB" --new-key --with-applier
printf 'libfoo\t1.0\tgated\t1\n' > "$R/var/lib/nethersec/holds.apply.tsv"
printf 'libfoo\n' > "$WORK/holds"; : > "$WORK/sticky-hold"
runit --uninstall
a_rc 1; a_has "still held"; a_has "libfoo"
a_file "$R/opt/nethersec/apply-aged-upgrades.sh"; a_file "$R/etc/systemd/system/nethersec-apply-aged.service"

# 20. --uninstall --purge also removes /etc/nethersec and /var/lib/nethersec, and takes
#     the IP-options drop and the module block off.
t "uninstall-purge"
rm -f "$WORK/sticky-hold" "$WORK/holds" "$R/var/lib/nethersec/holds.apply.tsv"
mkdir -p "$R/etc/modprobe.d"
: > "$R/etc/systemd/system/nethersec-ipv4-options-drop.service"
: > "$R/etc/modprobe.d/nethersec-blocked-modules.conf"
cat > "$BIN/nft" <<EOF
#!/bin/sh
echo "nft \$*" >> "$LOG"
case "\$*" in "list table ip nethersec_ipopt") exit 1 ;; esac
exit 0
EOF
chmod +x "$BIN/nft"
runit --uninstall --purge
rm -f "$BIN/nft"
a_rc 0
a_nofile "$R/opt/nethersec"; a_nofile "$R/etc/nethersec"; a_nofile "$R/var/lib/nethersec"
a_nofile "$R/etc/systemd/system/nethersec-ipv4-options-drop.service"; a_nofile "$R/etc/modprobe.d/nethersec-blocked-modules.conf"
a_call "nft delete table inet nethersec_flood"

# 21. without --purge, the hand-installed mitigations stay and the output says how to remove them.
t "uninstall-keeps-mitigations"
fresh; runit --source web1 --report-url "$HUB" --new-key
mkdir -p "$R/etc/modprobe.d"; : > "$R/etc/modprobe.d/nethersec-blocked-modules.conf"
runit --uninstall; a_rc 0
a_file "$R/etc/modprobe.d/nethersec-blocked-modules.conf"; a_has "kernel-modules-block.sh --remove"

echo ""
echo "install: $PASS passed, $FAIL failed"
rm -rf "$WORK" 2>/dev/null || :
[ "$FAIL" -eq 0 ]
