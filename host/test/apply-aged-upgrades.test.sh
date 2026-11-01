#!/usr/bin/env sh
# apply-aged-upgrades.test.sh: offline behavioral harness for the write-side
# release-age applier. Mocks apt-get / apt-mark / dpkg / the report transport via the
# script's env seams, feeds canned `apt-introspect` output, and asserts the risky
# logic WITHOUT touching a real box (runs on the dev machine / CI).
#
#   sh host/test/apply-aged-upgrades.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../apply-aged-upgrades.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/aat.$$"); mkdir -p "$WORK"
BIN="$WORK/bin"; STATE="$WORK/state"; mkdir -p "$BIN"
APPLYLOG="$WORK/apply.log"; MARKLOG="$WORK/mark.log"; CARDS="$WORK/cards.log"
NOW=1788000000
DAY=86400
PASS=0; FAIL=0; CUR=""

# --- mocks -----------------------------------------------------------------
# MOCK_SIM_TOUCH / MOCK_APPLY_TOUCH: a file to create while that step runs, to model
# apt-get update swapping a list into the lists dir mid-run.
cat > "$BIN/mock-apt-get" <<'EOF'
#!/bin/sh
case " $* " in
  *" -s "*)
    [ -n "${MOCK_SIM_TOUCH:-}" ] && : > "$MOCK_SIM_TOUCH"
    if [ -n "${MOCK_SIM_FILE:-}" ] && [ -f "$MOCK_SIM_FILE" ]; then cat "$MOCK_SIM_FILE"
    else seen=0; for a in "$@"; do [ "$seen" = 1 ] && echo "Inst $a [1.0] (2.0 Repo)"; [ "$a" = "--only-upgrade" ] && seen=1; done; fi
    exit ${MOCK_SIM_RC:-0} ;;
  *) [ -n "${MOCK_APPLY_TOUCH:-}" ] && : > "$MOCK_APPLY_TOUCH"
     echo "APPLIED:$*" >> "$MOCK_APPLY_LOG"
     [ -n "${MOCK_APPLY_OUT:-}" ] && printf '%s\n' "$MOCK_APPLY_OUT"
     exit ${MOCK_APPLY_RC:-0} ;;
esac
EOF
# `systemctl show -p <prop> --value <unit>` for the apt-busy check, so a CI box's own
# apt-daily never leaks in. apt-daily.service answers MOCK_SC_DAILY for its first
# MOCK_SC_DAILY_CALLS queries (every query when unset), then inactive.
cat > "$BIN/mock-systemctl" <<'EOF'
#!/bin/sh
unit=""; for a in "$@"; do unit="$a"; done
case "$unit" in
  apt-daily.service)
    n=0; [ -f "$MOCK_SC_COUNT" ] && n=$(cat "$MOCK_SC_COUNT"); n=$((n + 1)); echo "$n" > "$MOCK_SC_COUNT"
    if [ -z "${MOCK_SC_DAILY_CALLS:-}" ] || [ "$n" -le "$MOCK_SC_DAILY_CALLS" ]; then echo "${MOCK_SC_DAILY:-inactive}"; else echo inactive; fi ;;
  apt-daily-upgrade.service) echo "${MOCK_SC_UU:-dead}" ;;
esac
exit 0
EOF
cat > "$BIN/mock-apt-mark" <<'EOF'
#!/bin/sh
[ "${1:-}" = "showhold" ] && { [ -n "${MOCK_SHOWHOLD:-}" ] && printf '%s\n' "$MOCK_SHOWHOLD"; exit 0; }
echo "$*" >> "$MOCK_MARK_LOG"
# MOCK_UNHOLD_FAIL names a file: while it exists every unhold fails (apt's lock held)
[ "${1:-}" = "unhold" ] && [ -n "${MOCK_UNHOLD_FAIL:-}" ] && [ -f "$MOCK_UNHOLD_FAIL" ] && exit 1
exit 0
EOF
cat > "$BIN/mock-dpkg" <<'EOF'
#!/bin/sh
[ "${1:-}" = "--audit" ] && { [ -n "${MOCK_DPKG_AUDIT:-}" ] && printf '%s\n' "$MOCK_DPKG_AUDIT"; exit 0; }
exit 0
EOF
cat > "$BIN/mock-report" <<'EOF'
#!/bin/sh
ev=""; st=""; sv=""; dt=""
while [ $# -gt 0 ]; do case "$1" in --event) ev="$2"; shift 2;; --state) st="$2"; shift 2;; --severity) sv="$2"; shift 2;; --detail) dt="$2"; shift 2;; *) shift;; esac; done
# MOCK_REPORT_FAIL names a file: while it exists nothing is delivered (exit 1)
[ -n "${MOCK_REPORT_FAIL:-}" ] && [ -f "$MOCK_REPORT_FAIL" ] && exit 1
printf '%s|S=%s|V=%s|D=%s\n' "$ev" "$st" "$sv" "$dt" >> "$MOCK_CARDS"; exit 0
EOF
chmod +x "$BIN"/mock-*

# fields: name ver arch origin site archive trusted issec [source]; source defaults to
# the binary name (each package its own lockstep group) unless a 9th arg is given.
row() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "${9:-$1}"; }

setup() { # intro-content
  rm -rf "$STATE"; mkdir -p "$STATE"
  printf '%s\n' "$1" > "$WORK/intro.tsv"
  : > "$APPLYLOG"; : > "$MARKLOG"; : > "$CARDS"
  SIMFILE=""; DENYF="$WORK/nodeny"; DRY=0; APPLY_RC=0; SHOWHOLD=""; SIM_RC=0; DPKG_AUDIT=""
  LISTS_OVERRIDE=""; STAMP_OVERRIDE=""; KNI=""
  SC_DAILY=inactive; SC_DAILY_CALLS=""; SC_UU=dead; BUSYWAIT=0; SIM_TOUCH=""; APPLY_TOUCH=""; APPLY_OUT=""
  RUN_NOW=""; MAXP=8; ENA=1
  rm -f "$WORK/sc.count" "$WORK/report-fail"
}
runit() {
  env \
    HOSTSEC_APPLY_STATE_DIR="$STATE" \
    HOSTSEC_APPLY_INTROSPECT_CMD="cat $WORK/intro.tsv" \
    HOSTSEC_APPLY_APT_GET="$BIN/mock-apt-get" \
    HOSTSEC_APPLY_APT_MARK="$BIN/mock-apt-mark" \
    HOSTSEC_APPLY_DPKG="$BIN/mock-dpkg" \
    HOSTSEC_APPLY_REPORT_SCRIPT="$BIN/mock-report" \
    HOSTSEC_APPLY_LISTS_DIR="${LISTS_OVERRIDE:-$WORK/nolists}" \
    HOSTSEC_APPLY_UPDATE_STAMP="${STAMP_OVERRIDE:-$WORK/no-such-stamp}" \
    HOSTSEC_APPLY_NOW="${RUN_NOW:-$NOW}" \
    HOSTSEC_APPLY_MAX_POSTS="${MAXP:-8}" \
    HOSTSEC_SOURCE=testbox \
    HOSTSEC_APPLY_DRYRUN="$DRY" \
    HOSTSEC_APPLY_ENABLED="$ENA" \
    HOSTSEC_APPLY_KILL_FILE="$WORK/no-apply-kill" HOSTSEC_KILL_FILE="$WORK/no-kill" \
    HOSTSEC_APPLY_DENYLIST_FILE="$DENYF" \
    HOSTSEC_APPLY_KERNEL_NEWINSTALL_GLOBS="$KNI" \
    HOSTSEC_APPLY_SYSTEMCTL="$BIN/mock-systemctl" \
    HOSTSEC_APPLY_APT_BUSY_WAIT_SECS="$BUSYWAIT" HOSTSEC_APPLY_APT_BUSY_POLL_SECS=1 \
    MOCK_APPLY_LOG="$APPLYLOG" MOCK_MARK_LOG="$MARKLOG" MOCK_CARDS="$CARDS" \
    MOCK_SIM_FILE="$SIMFILE" MOCK_APPLY_RC="$APPLY_RC" MOCK_SHOWHOLD="$SHOWHOLD" \
    MOCK_SIM_RC="$SIM_RC" MOCK_DPKG_AUDIT="$DPKG_AUDIT" \
    MOCK_SC_DAILY="$SC_DAILY" MOCK_SC_DAILY_CALLS="$SC_DAILY_CALLS" MOCK_SC_UU="$SC_UU" \
    MOCK_SC_COUNT="$WORK/sc.count" MOCK_SIM_TOUCH="$SIM_TOUCH" MOCK_APPLY_TOUCH="$APPLY_TOUCH" \
    MOCK_APPLY_OUT="$APPLY_OUT" MOCK_REPORT_FAIL="$WORK/report-fail" \
    MOCK_UNHOLD_FAIL="$WORK/unhold-fail" \
    sh "$SCRIPT" 2>"$WORK/stderr"
  RC=$?
}

# --- assertions ------------------------------------------------------------
ok()   { PASS=$((PASS+1)); }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()    { CUR="$1"; }
a_applied()     { grep -q "APPLIED:.* $1\( \|$\)" "$APPLYLOG" 2>/dev/null && ok || bad "expected $1 to be APPLIED"; }
a_not_applied() { grep -q "APPLIED:.* $1\( \|$\)" "$APPLYLOG" 2>/dev/null && bad "expected $1 NOT applied" || ok; }
a_held()        { grep -q "^hold $1$" "$MARKLOG" 2>/dev/null && ok || bad "expected hold $1"; }
a_not_held()    { grep -q "^hold $1$" "$MARKLOG" 2>/dev/null && bad "expected $1 NOT held" || ok; }
a_unheld()      { grep -q "^unhold $1$" "$MARKLOG" 2>/dev/null && ok || bad "expected unhold $1"; }
a_card()        { grep -q "$1" "$CARDS" 2>/dev/null && ok || bad "expected a card matching '$1'"; }
a_nocard()      { grep -q "$1" "$CARDS" 2>/dev/null && bad "unexpected card '$1'" || ok; }
a_exit0()       { [ "$RC" = 0 ] && ok || bad "expected exit 0, got $RC"; }
a_card_sev()    { grep -q "^$1|S=[^|]*|V=$2" "$CARDS" 2>/dev/null && ok || bad "expected '$1' at severity '$2' (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_card_state()  { grep -q "^$1|S=$2|" "$CARDS" 2>/dev/null && ok || bad "expected '$1' state '$2' (got: $(tr '\n' ' ' <"$CARDS"))"; }

# ===========================================================================
# 1. crown jewel from a TRUSTED -updates origin -> fast-path (age 0), applied
t "fastpath-trusted-updates"
setup "$(row libwebp7 1.2 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
runit; a_applied libwebp7; a_not_held libwebp7; a_exit0

# 2. ordinary -updates package, first seen now -> HELD, not applied
t "gated-fresh"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
runit; a_not_applied somelib; a_held somelib
[ -f "$STATE/release-age-grace.tsv" ] && grep -q '^somelib	' "$STATE/release-age-grace.tsv" && ok || bad "expected somelib in grace tsv"

# 3. ordinary -updates package aged past grace (first-seen 5d ago) -> applied, and a
#    quiet non-paging "done" note posts as an `info` report
t "gated-aged-in"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
runit; a_applied somelib; a_exit0; a_card_state apply-applied triggered

# 4. third-party UNTRUSTED origin, fresh -> gated + held
t "thirdparty-gated"
setup "$(row docker-ce 5.0 amd64 Docker download.docker.com noble 0 0)"
runit; a_not_applied docker-ce; a_held docker-ce

# 5. crown-jewel NAME from an UNTRUSTED origin -> anomaly card, NOT fast-pathed (held)
t "untrusted-crownjewel-anomaly"
setup "$(row libssl3 9.9 amd64 EvilPPA ppa.launchpad.net noble 0 0)"
runit; a_not_applied libssl3; a_held libssl3; a_card "apply-anom-libssl3"

# 6. Ubuntu -security (trusted) -> u-u's job, applier IGNORES (not applied, not held)
t "security-trusted-ignored"
setup "$(row libc6 2.35 amd64 Ubuntu security.ubuntu.com noble-security 1 1)"
runit; a_not_applied libc6; a_not_held libc6; a_exit0

# 7. deny-listed package -> held indefinitely + deny card, not applied
t "deny-listed"
setup "$(row badpkg 1.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
DENYF="$WORK/deny"; printf 'badpkg\n' > "$DENYF"
runit; a_not_applied badpkg; a_held badpkg; a_card "apply-deny-badpkg"

# 8. aged-in package whose upgrade would REMOVE something -> refused + card
t "removal-refused"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
SIMFILE="$WORK/sim_remove"; printf 'Inst somelib [1.0] (2.0 Repo)\nRemv oldcruft [0.9]\n' > "$SIMFILE"
runit; a_not_applied somelib; a_card "apply-would-remove"

# 9. kernel fast-path: NEW versioned image install is expected, NOT rejected
t "kernel-newinstall-ok"
setup "$(row linux-image-generic 6.8.0.99 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
SIMFILE="$WORK/sim_kernel"; printf 'Inst linux-image-generic [6.8.0.98] (6.8.0.99 Repo)\nInst linux-image-6.8.0-99-generic (6.8.0-99 Repo)\n' > "$SIMFILE"
runit; a_applied linux-image-generic; a_nocard "apply-unexpected-newinstall"

# 10. aged-in package whose upgrade drags in a NON-kernel new install -> refused
t "unexpected-newinstall-refused"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
SIMFILE="$WORK/sim_newdep"; printf 'Inst somelib [1.0] (2.0 Repo)\nInst brandnewdep (1.0 Repo)\n' > "$SIMFILE"
runit; a_not_applied somelib; a_card "apply-unexpected-newinstall"

# 11. kill switch -> releases OUR holds and exits 0 (fails toward patched)
t "killswitch-releases-holds"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'oldheld\t1.0\tgated\t%s\n' $((NOW - 2*DAY)) > "$STATE/holds.apply.tsv"
touch "$STATE/../apply-disabled" 2>/dev/null
HOSTSEC_APPLY_KILL_FILE="$WORK/apply-disabled"; touch "$HOSTSEC_APPLY_KILL_FILE"
env HOSTSEC_APPLY_KILL_FILE="$WORK/apply-disabled" HOSTSEC_APPLY_STATE_DIR="$STATE" \
    HOSTSEC_APPLY_APT_MARK="$BIN/mock-apt-mark" HOSTSEC_APPLY_INTROSPECT_CMD="cat $WORK/intro.tsv" \
    HOSTSEC_APPLY_NOW="$NOW" MOCK_MARK_LOG="$MARKLOG" MOCK_APPLY_LOG="$APPLYLOG" MOCK_CARDS="$CARDS" \
    sh "$SCRIPT" 2>"$WORK/stderr"; RC=$?
a_exit0; a_unheld oldheld
# 11b. an unhold that fails (apt's lock held) keeps its row and is carded, so the next
#      run tries again; a hold nobody tracks would block the package's fixes for good.
t "killswitch-failed-unhold-kept-and-carded"
printf 'oldheld\t1.0\tgated\t%s\n' $((NOW - 2*DAY)) > "$STATE/holds.apply.tsv"
: > "$CARDS"; touch "$WORK/unhold-fail"
killrun() {
  env HOSTSEC_APPLY_KILL_FILE="$WORK/apply-disabled" HOSTSEC_APPLY_STATE_DIR="$STATE" \
    HOSTSEC_APPLY_APT_MARK="$BIN/mock-apt-mark" HOSTSEC_APPLY_INTROSPECT_CMD="cat $WORK/intro.tsv" \
    HOSTSEC_APPLY_REPORT_SCRIPT="$BIN/mock-report" HOSTSEC_SOURCE=testbox \
    HOSTSEC_APPLY_NOW="$NOW" MOCK_MARK_LOG="$MARKLOG" MOCK_APPLY_LOG="$APPLYLOG" MOCK_CARDS="$CARDS" \
    MOCK_SHOWHOLD="$1" MOCK_UNHOLD_FAIL="$WORK/unhold-fail" \
    sh "$SCRIPT" 2>"$WORK/stderr"; RC=$?
}
killrun oldheld
a_exit0; a_card "apply-unhold-failed-oldheld"
grep -q "^oldheld	" "$STATE/holds.apply.tsv" 2>/dev/null && ok || bad "a failed unhold must keep its row"
rm -f "$WORK/unhold-fail"; killrun ""
a_exit0; [ -s "$STATE/holds.apply.tsv" ] && bad "the row must go once the unhold works" || ok
rm -f "$WORK/apply-disabled"

# 12. episode past the hard ceiling but still not applied -> stuck card
t "ceiling-stuck"
setup "$(row stuckpkg 3.0 amd64 Docker download.docker.com noble 0 0)"
printf 'stuckpkg\t%s\t2\t3.0\n' $((NOW - 12*DAY)) > "$STATE/episode.apply.tsv"
runit; a_not_applied stuckpkg; a_held stuckpkg; a_card "apply-stuck-stuckpkg"

# 13. hold RECONCILE: a package we held that has now aged in gets UNHELD then applied
t "hold-reconcile-unhold-on-agein"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
printf 'somelib\t2.0\tgated\t%s\n' $((NOW - 5*DAY)) > "$STATE/holds.apply.tsv"
runit; a_unheld somelib; a_applied somelib

# 13b. the same release while apt's lock is held: the unhold fails, so the row stays and a
#      card says so; the next run releases it and drops the row.
t "hold-reconcile-failed-unhold-kept"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
printf 'somelib\t2.0\tgated\t%s\n' $((NOW - 5*DAY)) > "$STATE/holds.apply.tsv"
SHOWHOLD="somelib"; touch "$WORK/unhold-fail"
runit; a_exit0; a_card "apply-unhold-failed-somelib"
grep -q "^somelib	" "$STATE/holds.apply.tsv" 2>/dev/null && ok || bad "a failed unhold must keep its row"
rm -f "$WORK/unhold-fail"; SHOWHOLD=""
runit; a_exit0; a_unheld somelib
grep -q "^somelib	" "$STATE/holds.apply.tsv" 2>/dev/null && bad "the row must go once the unhold works" || ok

# 14. FOREIGN hold (not in our state) is never touched
t "foreign-hold-respected"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
# an admin holds 'adminpkg' but it is NOT in our holds.apply.tsv and NOT upgradable
runit
grep -q "^unhold adminpkg$" "$MARKLOG" 2>/dev/null && bad "must not unhold a foreign hold" || ok

# 15. introspection failure -> fail closed (nothing applied, nothing held, card + exit0)
t "introspect-fail-closed"
setup ""
env HOSTSEC_APPLY_STATE_DIR="$STATE" HOSTSEC_APPLY_INTROSPECT_CMD="false" \
    HOSTSEC_APPLY_APT_GET="$BIN/mock-apt-get" HOSTSEC_APPLY_APT_MARK="$BIN/mock-apt-mark" \
    HOSTSEC_APPLY_DPKG="$BIN/mock-dpkg" HOSTSEC_APPLY_REPORT_SCRIPT="$BIN/mock-report" \
    HOSTSEC_APPLY_LISTS_DIR="$WORK/nolists" HOSTSEC_APPLY_NOW="$NOW" HOSTSEC_SOURCE=testbox \
    HOSTSEC_APPLY_DENYLIST_FILE="$WORK/nodeny" \
    HOSTSEC_APPLY_SYSTEMCTL="$BIN/mock-systemctl" HOSTSEC_APPLY_APT_BUSY_WAIT_SECS=0 MOCK_SC_COUNT="$WORK/sc.count" \
    MOCK_APPLY_LOG="$APPLYLOG" MOCK_MARK_LOG="$MARKLOG" MOCK_CARDS="$CARDS" MOCK_SIM_FILE="" MOCK_APPLY_RC=0 \
    sh "$SCRIPT" 2>"$WORK/stderr"; RC=$?
a_exit0; a_card "apply-introspect-unavailable"
[ -s "$APPLYLOG" ] && bad "nothing should be applied when introspection fails" || ok

# 16. SIGNED third-party crown jewel (trusted=1 but NON-Canonical origin) -> the real
#     supply-chain attack: MUST be gated + anomaly-carded, NOT fast-pathed.
t "signed-thirdparty-crownjewel-gated"
setup "$(row libssl3 9.9 amd64 Docker download.docker.com noble 1 0)"
runit; a_not_applied libssl3; a_held libssl3; a_card "apply-anom-libssl3"

# 17. SIGNED third-party self-labeling its suite '-security' (trusted=1, non-Canonical
#     site) must NOT reach the 'uu/ignore' branch and must NOT release an existing hold.
t "signed-thirdparty-security-spoof-gated"
setup "$(row evilpkg 2.0 amd64 EvilRepo evil.example.com noble-security 1 1)"
printf 'evilpkg\t1.5\tgated\t%s\n' $((NOW - 2*DAY)) > "$STATE/holds.apply.tsv"
runit; a_not_applied evilpkg
grep -q "^unhold evilpkg$" "$MARKLOG" 2>/dev/null && bad "spoofed -security must NOT release the hold" || ok

# 18. FOREIGN admin hold on an UPGRADABLE (even aged-in) package -> left untouched.
t "foreign-hold-upgradable-untouched"
setup "$(row adminpin 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'adminpin\t2.0\tamd64\t%s\n' $((NOW - 9*DAY)) > "$STATE/first-seen.apply.tsv"
SHOWHOLD="adminpin"
runit; a_not_applied adminpin
grep -q "^hold adminpin$" "$MARKLOG" 2>/dev/null && bad "must not adopt a foreign pin" || ok
grep -q "^unhold adminpin$" "$MARKLOG" 2>/dev/null && bad "must not unhold a foreign pin" || ok

# 19. REALISTIC apt output: a new-install line carries an [amd64] bracket too -> the
#     guard must still refuse it (the '[oldver]' vs '(' discriminator, not 'any [').
t "realistic-newinstall-refused"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
SIMFILE="$WORK/sim_realnew"
printf 'Inst somelib [1.0] (2.0 Ubuntu:24.04/noble [amd64])\nInst brandnewdep (1.0 Ubuntu:24.04/noble [amd64])\n' > "$SIMFILE"
runit; a_not_applied somelib; a_card "apply-unexpected-newinstall"

# 20. crown jewel via CANONICAL -security (trusted + ubuntu.com) held from a prior
#     -updates soak -> released and fast-applied immediately (held-fix beats uu).
t "held-then-canonical-security-fastpath"
setup "$(row openssl 3.1 amd64 Ubuntu security.ubuntu.com noble-security 1 1)"
printf 'openssl\t3.0\tgated\t%s\n' $((NOW - 1*DAY)) > "$STATE/holds.apply.tsv"
SHOWHOLD="openssl"
runit; a_applied openssl; a_unheld openssl

# 21. the guarded APPLY fails (apt rc!=0) -> apply-failed PAGES critical
t "apply-write-failure-critical"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
APPLY_RC=1
runit; a_card_sev apply-failed critical

# 22. the pre-apply SIMULATION fails (apt -s rc!=0) -> apply-sim-failed PAGES critical
t "apply-sim-failure-critical"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
SIM_RC=1
runit; a_card_sev apply-sim-failed critical; a_not_applied somelib

# 23. dpkg in a broken state (dpkg --audit non-empty) -> apply-dpkg-broken PAGES critical,
#     applier stands down before touching anything
t "apply-dpkg-broken-critical"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
DPKG_AUDIT="somepkg: dependency problems"
runit; a_card_sev apply-dpkg-broken critical; a_not_applied somelib

# 24. STALE list mtimes but a FRESH apt update-success stamp (a quiet publishing window,
#     e.g. a weekend where no pocket republished) -> NOT treated as stale: no card, and
#     the applier PROCEEDS (an aged-in package still gets applied, not stood down).
t "stalecache-fresh-updatestamp-proceeds"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
LISTS_OVERRIDE="$WORK/lists24"; mkdir -p "$LISTS_OVERRIDE"
: > "$LISTS_OVERRIDE/mirror_dists_noble_InRelease"; touch -d "@$((NOW - 60*3600))" "$LISTS_OVERRIDE/mirror_dists_noble_InRelease"
STAMP_OVERRIDE="$WORK/updstamp24"; : > "$STAMP_OVERRIDE"; touch -d "@$((NOW - 3*3600))" "$STAMP_OVERRIDE"
runit; a_nocard apply-stale-cache; a_applied somelib; a_exit0

# 25. STALE list mtimes AND a STALE update-success stamp -> apt-daily genuinely frozen:
#     card (warning) + stand down (nothing applied even though somelib is aged in).
t "stalecache-stale-updatestamp-cards"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
LISTS_OVERRIDE="$WORK/lists25"; mkdir -p "$LISTS_OVERRIDE"
: > "$LISTS_OVERRIDE/mirror_dists_noble_InRelease"; touch -d "@$((NOW - 60*3600))" "$LISTS_OVERRIDE/mirror_dists_noble_InRelease"
STAMP_OVERRIDE="$WORK/updstamp25"; : > "$STAMP_OVERRIDE"; touch -d "@$((NOW - 60*3600))" "$STAMP_OVERRIDE"
runit; a_card_sev apply-stale-cache warning; a_not_applied somelib

# 26. STALE list mtimes with the update-success stamp ABSENT -> can't confirm apt-daily
#     health, so fall back to the conservative behavior: card + stand down.
t "stalecache-missing-updatestamp-cards"
setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
LISTS_OVERRIDE="$WORK/lists26"; mkdir -p "$LISTS_OVERRIDE"
: > "$LISTS_OVERRIDE/mirror_dists_noble_InRelease"; touch -d "@$((NOW - 60*3600))" "$LISTS_OVERRIDE/mirror_dists_noble_InRelease"
STAMP_OVERRIDE="$WORK/updstamp26-absent"   # never created
runit; a_card_sev apply-stale-cache warning; a_not_applied somelib

# 27. LOCKSTEP: a crown-jewel (libkrb5-3, fast-path) and a canonical gated sibling
#     (libk5crypto3) from the SAME source ship in lockstep. The sibling must be promoted
#     to apply WITH the crown-jewel (not left held), so `--only-upgrade` is satisfiable.
t "lockstep-fastpath-pulls-canonical-gated-sibling"
setup "$(printf '%s\n%s' \
  "$(row libkrb5-3 1.21.3-1ubuntu0.2 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0 krb5)" \
  "$(row libk5crypto3 1.21.3-1ubuntu0.2 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0 krb5)")"
runit; a_applied libkrb5-3; a_applied libk5crypto3; a_not_held libk5crypto3; a_exit0

# 28. LOCKSTEP guard: a NON-CANONICAL package that self-claims the crown-jewel's source
#     must NOT be promoted (no age-0 hole via a spoofed source name); stays gated + held.
t "lockstep-does-not-pull-noncanonical-shadow"
setup "$(printf '%s\n%s' \
  "$(row libkrb5-3 1.21.3-1ubuntu0.2 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0 krb5)" \
  "$(row libk5crypto3 9.9 amd64 EvilRepo evil.example.com noble 0 0 krb5)")"
runit; a_applied libkrb5-3; a_not_applied libk5crypto3; a_held libk5crypto3

# 29. LOCKSTEP guard: a DENY-listed sibling of a fast-pathed source is NOT promoted -
#     the admin's deny beats lockstep co-apply (held indefinitely + deny card).
t "lockstep-does-not-pull-denylisted-sibling"
setup "$(printf '%s\n%s' \
  "$(row libkrb5-3 1.21.3-1ubuntu0.2 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0 krb5)" \
  "$(row libk5crypto3 1.21.3-1ubuntu0.2 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0 krb5)")"
DENYF="$WORK/deny29"; printf 'libk5crypto3\n' > "$DENYF"
runit; a_applied libkrb5-3; a_not_applied libk5crypto3; a_held libk5crypto3; a_card "apply-deny-libk5crypto3"

# 30. LOCKSTEP guard (version-blind soak-bypass): a canonical gated package that shares
#     only the SOURCE NAME of a fast-pathed crown-jewel but is a DIFFERENT version/upload
#     must NOT be promoted; its release-age soak stands, no age-0 ride-in on an unrelated
#     crown-jewel version.
t "lockstep-does-not-pull-different-version-sibling"
setup "$(printf '%s\n%s' \
  "$(row libkrb5-3 1.21.3-1ubuntu0.2 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0 krb5)" \
  "$(row libpwn 9.9-different-upload amd64 Ubuntu archive.ubuntu.com noble-updates 1 0 krb5)")"
runit; a_applied libkrb5-3; a_not_applied libpwn; a_held libpwn

# 31. DRY-RUN must not false-page the ceiling. An
#     aged-in package with a clean simulation would be applied live, ending its episode;
#     dry-run applies nothing, so the episode must still end. Otherwise the package's NEXT
#     release inherits days of dry-run "pending" and pages "stuck" at CEILING_DAYS.
#     stuckpkg (still soaking, episode past the ceiling) is NOT would-apply: its episode
#     must survive and it must keep paging, so ending episodes can't hide a real page.
t "dryrun-would-apply-ends-episode"
setup "$(printf '%s\n%s' \
  "$(row vendor-plugin 1.4.0 amd64 Docker download.docker.com noble 1 0)" \
  "$(row stuckpkg 3.0 amd64 Docker download.docker.com noble 0 0)")"
printf 'vendor-plugin\t1.4.0\tamd64\t%s\nstuckpkg\t3.0\tamd64\t%s\n' \
  $((NOW - 9*DAY)) $((NOW - 1*DAY)) > "$STATE/first-seen.apply.tsv"
printf 'vendor-plugin\t%s\t1\t1.4.0\nstuckpkg\t%s\t2\t3.0\n' \
  $((NOW - 9*DAY)) $((NOW - 12*DAY)) > "$STATE/episode.apply.tsv"
DRY=1
runit; a_not_applied vendor-plugin; a_nocard apply-stuck-vendor-plugin
a_card_sev apply-stuck-stuckpkg critical
[ -f "$STATE/episode.apply.tsv" ] && ok || bad "episode state must survive a dry-run"
grep -q "^vendor-plugin$(printf '\t')" "$STATE/episode.apply.tsv" 2>/dev/null \
  && bad "a dry-run would-apply must end the episode" || ok
grep -q "^stuckpkg$(printf '\t')" "$STATE/episode.apply.tsv" 2>/dev/null \
  && ok || bad "a dry-run must keep episodes of packages it would not apply"
# two days later a new vendor-plugin release (fresh soak) arrives: 11d after its first sighting.
# stuckpkg is still soaking (3d < 4d), so it stays stuck.
SAVED_NOW=$NOW; NOW=$((NOW + 2*DAY))
printf '%s\n%s\n' \
  "$(row vendor-plugin 1.4.1 amd64 Docker download.docker.com noble 1 0)" \
  "$(row stuckpkg 3.0 amd64 Docker download.docker.com noble 0 0)" > "$WORK/intro.tsv"
: > "$CARDS"
runit; a_held vendor-plugin; a_nocard apply-stuck-vendor-plugin; a_exit0
a_card_sev apply-stuck-stuckpkg critical
NOW=$SAVED_NOW

# ===========================================================================
# KERNEL NEW-INSTALL ALLOW-LIST (Ubuntu 26.04). A kernel meta
# bump newly installs linux-image-<V>-generic + linux-modules-<V>-generic AND
# linux-main-modules-zfs-<V>-generic (linux-modules Depends on the zfs split). The zfs
# package was not on the list, so EVERY run refused the whole set as "un-aged".
K26_META="$(row linux-image-virtual 7.0.0-14.14 amd64 Ubuntu archive.ubuntu.com resolute-updates 1 0 linux-meta)"
k26_sim() { # extra Inst lines... -> writes the realistic 26.04 simulation to $SIMFILE
  SIMFILE="$WORK/sim_k26"
  {
    printf '%s\n' \
      'Inst linux-image-7.0.0-14-generic (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])' \
      'Inst linux-modules-7.0.0-14-generic (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])' \
      'Inst linux-main-modules-zfs-7.0.0-14-generic (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])' \
      'Inst linux-image-virtual [7.0.0-11.11] (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])'
    for x in "$@"; do printf '%s\n' "$x"; done
    printf '%s\n' \
      'Conf linux-modules-7.0.0-14-generic (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])' \
      'Conf linux-image-virtual (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])'
  } > "$SIMFILE"
}

# 32. LIVE: the exact 26.04 new-install set is accepted -> applied, no refusal card.
t "kernel-2604-main-modules-newinstall-live"
setup "$K26_META"; k26_sim
runit; a_applied linux-image-virtual; a_nocard apply-unexpected-newinstall; a_exit0

# 33. DRY-RUN: same set -> logged as would-apply (not applied), no refusal card.
t "kernel-2604-main-modules-newinstall-dryrun"
setup "$K26_META"; k26_sim; DRY=1
runit; a_not_applied linux-image-virtual; a_nocard apply-unexpected-newinstall; a_exit0
grep -q "DRYRUN: would apply: linux-image-virtual" "$WORK/stderr" 2>/dev/null && ok || bad "expected a would-apply log for linux-image-virtual"

# 34. a NON-kernel new install next to the kernel set is still refused (whole set).
t "kernel-2604-plus-nonkernel-newinstall-refused"
setup "$K26_META"; k26_sim 'Inst brandnewdep (1.0 Ubuntu:26.04/resolute-updates [amd64])'
runit; a_not_applied linux-image-virtual; a_card apply-unexpected-newinstall

# 35. the default list stays narrow: a versioned kernel family not seen pulled in
#     (linux-tools-*) is NOT exempt by default.
t "kernel-tools-not-in-default-list"
setup "$K26_META"; k26_sim 'Inst linux-tools-7.0.0-14-generic (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])'
runit; a_not_applied linux-image-virtual; a_card apply-unexpected-newinstall

# 36. HOSTSEC_APPLY_KERNEL_NEWINSTALL_GLOBS REPLACES the default: without
#     linux-main-modules-* the zfs split is refused again.
t "kernel-globs-override-replaces-default"
setup "$K26_META"; k26_sim; KNI="linux-image-* linux-modules-*"
runit; a_not_applied linux-image-virtual; a_card apply-unexpected-newinstall

# 37. ...and can extend it for a box whose metas pull an extra family.
t "kernel-globs-override-extends"
setup "$K26_META"; k26_sim 'Inst linux-tools-7.0.0-14-generic (7.0.0-14.14 Ubuntu:26.04/resolute-updates [amd64])'
KNI="linux-image-* linux-modules-* linux-main-modules-* linux-tools-*"
runit; a_applied linux-image-virtual; a_nocard apply-unexpected-newinstall

# 38. the glob list is matched as PATTERNS, never pathname-expanded against the cwd: a
#     file named like a pattern match must not turn 'linux-main-modules-*' literal.
t "kernel-globs-not-pathname-expanded"
setup "$K26_META"; k26_sim
mkdir -p "$WORK/globtrap"; : > "$WORK/globtrap/linux-main-modules-trap"
SAVED_PWD=$(pwd); cd "$WORK/globtrap" || bad "cd globtrap"
runit
cd "$SAVED_PWD" || :
a_applied linux-image-virtual; a_nocard apply-unexpected-newinstall

# ===========================================================================
# ORDERING vs unattended-upgrades (static). u-u skips a package whose hold went stale
# at the list refresh when the applier's next hourly run comes AFTER u-u. The drop-in makes apt-daily-upgrade.service start
# the applier (and wait for it) right before u-u. These pin the pieces that make that
# work and the ones that would deadlock it. (install.sh's part, laying the drop-in down
# and taking it away again, is covered by install.test.sh.)
DROPIN="$HERE/../apt-daily-upgrade.nethersec.conf"
UNIT_IN="$HERE/../nethersec-apply-aged.service"

# 39. the drop-in exists and starts the applier, '-'-prefixed, blocking, in [Service].
t "uu-dropin-starts-applier-first"
[ -f "$DROPIN" ] && ok || bad "drop-in $DROPIN is missing"
awk '/^\[/{sec=$0; next} sec=="[Service]" && /^ExecStartPre=-(\/usr)?\/bin\/systemctl start nethersec-apply-aged\.service[[:space:]]*$/{f=1} END{exit !f}' "$DROPIN" 2>/dev/null \
  && ok || bad "drop-in lacks [Service] ExecStartPre=-/bin/systemctl start nethersec-apply-aged.service"
grep -Eq '^[[:space:]]*ExecStartPre=[^-].*nethersec-apply-aged' "$DROPIN" 2>/dev/null \
  && bad "an un-prefixed ExecStartPre would let an applier failure stop u-u" || ok
grep -Eq '^[[:space:]]*ExecStartPre=[[:space:]]*$' "$DROPIN" 2>/dev/null \
  && bad "an empty ExecStartPre= would wipe the stock wait-online step" || ok
grep -Eq '^[^#]*--no-block' "$DROPIN" 2>/dev/null \
  && bad "--no-block would let u-u start before the applier finished" || ok
grep -q "$(printf '\r')" "$DROPIN" 2>/dev/null \
  && bad "drop-in has CRLF (systemd would read a unit name ending in CR)" || ok

# 39b. the SECOND ExecStartPre waits while the applier is still running. The blocking
#      start above can return EARLY: a live applier that upgrades systemd makes PID 1
#      re-exec (systemd's postinst), which drops systemctl's bus connection while dpkg is
#      still running. u-u must still not start until the applier has finished, or it
#      cannot take the dpkg lock and skips the whole day. This runs the exact shell the
#      drop-in hands to /bin/sh (systemd's '$$' un-escaped) against a scripted
#      `systemctl is-active` and a no-op `sleep`.
t "uu-dropin-waits-while-applier-runs"
WAITLINE=$(awk '/^\[/{sec=$0; next} sec=="[Service]" && /^ExecStartPre=-\/bin\/sh -c /{print; exit}' "$DROPIN" 2>/dev/null)
[ -n "$WAITLINE" ] && ok || bad "drop-in lacks the [Service] ExecStartPre=-/bin/sh -c wait line"
awk '/^\[/{sec=$0; next} sec=="[Service]" && /^ExecStartPre=/{n++; if (/systemctl start nethersec-apply-aged/) s=n; if (/^ExecStartPre=-\/bin\/sh -c /) w=n} END{exit !(s && w && w > s)}' "$DROPIN" 2>/dev/null \
  && ok || bad "the wait line must come AFTER the start line"
# systemd expands $VAR / ${VAR} in Exec lines (to empty when unset), so every '$' meant
# for the shell must be written '$$'.
printf '%s' "$WAITLINE" | sed 's/\$\$//g' | grep -q '\$' \
  && bad "the wait line has an unescaped \$ (systemd would expand it; write \$\$)" || ok
WAITBODY=$(printf '%s\n' "$WAITLINE" | sed "s/^[^']*'//; s/'[[:space:]]*\$//; s/\\\$\\\$/\$/g")
SYSBIN="$WORK/sysbin"; mkdir -p "$SYSBIN"
cat > "$SYSBIN/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$MOCK_SC_LOG"
n=$(wc -l < "$MOCK_SC_LOG" | tr -d ' ')
s=$(sed -n "${n}p" "$MOCK_SC_SEQ")
case "$s" in
  FAIL) echo "Failed to connect to bus: Connection refused" >&2; exit 1 ;;
  active) echo active; exit 0 ;;
  *) [ -n "$s" ] && echo "$s"; exit 3 ;;
esac
EOF
cat > "$SYSBIN/sleep" <<'EOF'
#!/bin/sh
echo "$*" >> "$MOCK_SLEEP_LOG"; exit 0
EOF
chmod +x "$SYSBIN/systemctl" "$SYSBIN/sleep"
dropin_wait() { # body state... -> run the wait; sets WRC, WCALLS (is-active calls), WSLEEPS
  dw_b="$1"; shift
  printf '%s\n' "$@" > "$WORK/sc.seq"; : > "$WORK/sc.log"; : > "$WORK/sleep.log"
  env PATH="$SYSBIN:$PATH" MOCK_SC_LOG="$WORK/sc.log" MOCK_SC_SEQ="$WORK/sc.seq" \
      MOCK_SLEEP_LOG="$WORK/sleep.log" sh -c "$dw_b" >/dev/null 2>&1
  WRC=$?
  WCALLS=$(wc -l < "$WORK/sc.log" | tr -d ' '); WSLEEPS=$(wc -l < "$WORK/sleep.log" | tr -d ' ')
}
# still running -> PID 1 mid re-exec (connection refused, then no answer) -> still
# running -> finished: waits through all of it, then lets u-u go.
dropin_wait "$WAITBODY" activating FAIL "" activating inactive
[ "$WRC" = 0 ] && [ "$WCALLS" = 5 ] && [ "$WSLEEPS" = 4 ] && ok \
  || bad "expected 5 is-active polls + 4 sleeps then exit 0 (rc=$WRC calls=$WCALLS sleeps=$WSLEEPS)"
grep -qxv '5' "$WORK/sleep.log" 2>/dev/null && bad "the wait must sleep 5s per poll" || ok
grep -qxv 'is-active nethersec-apply-aged.service' "$WORK/sc.log" 2>/dev/null \
  && bad "the wait must only poll is-active on the applier unit (got: $(tr '\n' ' ' <"$WORK/sc.log"))" || ok
# the normal case: the start already waited, so one poll and no sleep
for st in inactive failed active; do
  dropin_wait "$WAITBODY" "$st"
  [ "$WRC" = 0 ] && [ "$WCALLS" = 1 ] && [ "$WSLEEPS" = 0 ] && ok \
    || bad "state '$st': expected one poll, no sleep, exit 0 (rc=$WRC calls=$WCALLS sleeps=$WSLEEPS)"
done
# bounded: it gives up after its poll budget (shrunk to 3 here) even if the applier never
# finishes, so u-u is never held back for good...
dropin_wait "$(printf '%s' "$WAITBODY" | sed 's/-lt 360/-lt 3/')" activating activating activating activating activating
[ "$WCALLS" = 3 ] && [ "$WSLEEPS" = 3 ] && ok || bad "the wait must stop after its poll budget (calls=$WCALLS sleeps=$WSLEEPS)"
# ...and the real budget (polls x sleep) covers exactly the applier's own start timeout.
wl_n=$(printf '%s' "$WAITLINE" | sed -n 's/.*-lt \([0-9][0-9]*\).*/\1/p')
wl_s=$(printf '%s' "$WAITLINE" | sed -n 's/.*sleep \([0-9][0-9]*\).*/\1/p')
wl_t=$(sed -n 's/^TimeoutStartSec=\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$UNIT_IN" 2>/dev/null)
[ -n "$wl_n" ] && [ -n "$wl_s" ] && [ -n "$wl_t" ] && [ $((wl_n * wl_s)) -eq "$wl_t" ] && ok \
  || bad "wait budget ${wl_n:-?} x ${wl_s:-?}s must equal the applier's TimeoutStartSec=${wl_t:-?}"

# 40. the applier unit never depends on / orders after apt-daily-upgrade (deadlock), and
#     stays Type=oneshot (so `systemctl start` blocks until the run has finished).
t "applier-unit-never-waits-on-uu"
[ -f "$UNIT_IN" ] && ok || bad "unit template $UNIT_IN is missing"
grep -Eiq '^[[:space:]]*(After|Requires|Wants|Requisite|BindsTo|PartOf|Upholds)[[:space:]]*=.*apt-daily-upgrade' "$UNIT_IN" 2>/dev/null \
  && bad "nethersec-apply-aged.service must not depend on / order after apt-daily-upgrade.service" || ok
grep -Eq '^[[:space:]]*Type=oneshot[[:space:]]*$' "$UNIT_IN" 2>/dev/null \
  && ok || bad "nethersec-apply-aged.service must stay Type=oneshot"

# ===========================================================================
# 42. an origin label containing a space is never canonical ("Ubuntu UbuntuESM" must not
#     substring-match the allow-list): a crown-jewel -security row from it is an
#     anomaly (gated + held + carded), not u-u's job.
t "origin-with-space-not-canonical"
setup "$(row libc6 2.99 amd64 'Ubuntu UbuntuESM' archive.ubuntu.com resolute-security 1 1)"
runit; a_held libc6; a_not_applied libc6; a_card apply-anom-libc6

# ===========================================================================
# APT COLLISIONS. The hourly applier and apt-daily fire in the same second. `apt-get
# update` swaps a changed list in (it deletes the old file, then renames the new one),
# the lock-free `apt-get -s` hits the gap, rc=100, and a "simulation failed" page would
# fire for a run that only collided with apt's own refresh.
aged_somelib() {  # an aged-in, applyable package
  setup "$(row somelib 2.0 amd64 Ubuntu archive.ubuntu.com noble-updates 1 0)"
  printf 'somelib\t2.0\tamd64\t%s\n' $((NOW - 5*DAY)) > "$STATE/first-seen.apply.tsv"
}
old_lists() {  # name -> an existing lists dir with an old mtime, so a swap-in shows
  LISTS_OVERRIDE="$WORK/$1"; mkdir -p "$LISTS_OVERRIDE"; touch -d "@$((NOW - DAY))" "$LISTS_OVERRIDE"
}
LISTGAP='E: Could not open file /var/lib/apt/lists/pkgs.example.com_stable_ubuntu_dists_noble_main_binary-amd64_Packages - open (2: No such file or directory)'
COLLIDES="$STATE/apply-apt-collisions"

# 43. a list is swapped in while the simulation runs and it fails rc=100 ->
#     no card, nothing applied, apt's error line in the journal, streak 1.
t "sim-collides-with-list-swap-no-page"
aged_somelib; old_lists lists43; SIM_TOUCH="$LISTS_OVERRIDE/swapped-in"; SIM_RC=100
SIMFILE="$WORK/sim43"; printf '%s\n' 'Reading package lists...' "$LISTGAP" > "$SIMFILE"
runit; a_nocard apply-sim-failed; a_not_applied somelib; a_exit0
grep -q "simulation failed rc=100: E: Could not open file" "$WORK/stderr" 2>/dev/null && ok || bad "apt's error line must reach the journal"
[ "$(cat "$COLLIDES" 2>/dev/null)" = 1 ] && ok || bad "expected a collision streak of 1"

# 44. ...but the third collision in a row pages as before, with apt's error on the card.
t "sim-collision-streak-pages"
aged_somelib; old_lists lists44; SIM_TOUCH="$LISTS_OVERRIDE/swapped-in"; SIM_RC=100
SIMFILE="$WORK/sim44"; printf '%s\n' "$LISTGAP" > "$SIMFILE"
printf '2\n' > "$COLLIDES"
runit; a_card_sev apply-sim-failed critical; a_not_applied somelib
grep -q "^apply-sim-failed|.*rc=100 (E: Could not open file" "$CARDS" 2>/dev/null && ok || bad "the card must carry apt's error line"

# 45. a simulation failure with no apt activity is real: it pages at once, with the line.
t "sim-real-failure-pages-with-apt-error"
aged_somelib; old_lists lists45; SIM_RC=100
SIMFILE="$WORK/sim45"; printf '%s\n' 'E: Unable to correct problems, you have held broken packages.' > "$SIMFILE"
runit; a_card_sev apply-sim-failed critical; a_not_applied somelib
grep -q "^apply-sim-failed|.*held broken packages" "$CARDS" 2>/dev/null && ok || bad "the card must carry apt's error line"
[ -f "$COLLIDES" ] && bad "a failure with no apt activity is not a collision" || ok

# 46. apt-daily is running when the applier starts -> it waits, then applies normally.
t "waits-for-apt-daily-then-applies"
aged_somelib; SC_DAILY=activating; SC_DAILY_CALLS=1; BUSYWAIT=30
runit; a_applied somelib; a_nocard apply-sim-failed; a_exit0
grep -q "waiting up to 30s: apt-daily.service running" "$WORK/stderr" 2>/dev/null && ok || bad "expected a wait log"

# 47. apt-daily still running after the wait -> stand down before touching anything: no
#     card, no hold change, nothing applied, heartbeat still written.
t "apt-still-busy-stands-down"
aged_somelib; SC_DAILY=activating
runit; a_not_applied somelib; a_exit0
[ -s "$CARDS" ] && bad "a stand-down posts no card (got: $(tr '\n' ' ' <"$CARDS"))" || ok
[ -s "$MARKLOG" ] && bad "a stand-down changes no hold" || ok
[ -f "$STATE/apply-heartbeat" ] && ok || bad "a stand-down still writes the heartbeat"

# 48. u-u's install run counts as busy; u-u waiting on this unit (start-pre, the u-u
#     drop-in) does not, or the daily run would never apply.
t "uu-running-is-busy-uu-start-pre-is-not"
aged_somelib; SC_UU=start
runit; a_not_applied somelib; a_nocard apply-sim-failed
aged_somelib; SC_UU=start-pre
runit; a_applied somelib

# 49. lists swapped in after classification (simulation clean on the NEW lists) -> do not
#     apply: install --only-upgrade would take a candidate that never soaked.
t "lists-moved-before-apply-not-applied"
aged_somelib; old_lists lists49; SIM_TOUCH="$LISTS_OVERRIDE/swapped-in"
runit; a_not_applied somelib; a_exit0
[ -s "$CARDS" ] && bad "no card for a moved-lists stand-down (got: $(tr '\n' ' ' <"$CARDS"))" || ok

# 49b. ...and the third such run in a row still installs nothing: it pages instead of
#      running the live install on lists that changed after the set was sorted.
t "lists-moved-streak-pages-never-applies"
aged_somelib; old_lists lists49b; SIM_TOUCH="$LISTS_OVERRIDE/swapped-in"
printf '2\n' > "$COLLIDES"
runit; a_not_applied somelib; a_exit0; a_card_sev apply-apt-collisions critical
grep -q "^apply-apt-collisions|.*Set: somelib" "$CARDS" 2>/dev/null && ok || bad "the card must name the set it did not apply"
grep -q "applied: somelib" "$WORK/stderr" 2>/dev/null && bad "a moved-lists run must never log an apply" || ok
grep -q "apt collision 3 in a row, applied nothing" "$WORK/stderr" 2>/dev/null && ok || bad "the journal must say the streak and that nothing was applied"
[ "$(cat "$COLLIDES" 2>/dev/null)" = 3 ] && ok || bad "the streak must keep counting (got: $(cat "$COLLIDES" 2>/dev/null))"

# 50. the live apply collides with a list swap -> no page, apt's error in the journal.
t "apply-collision-no-page"
aged_somelib; old_lists lists50; APPLY_TOUCH="$LISTS_OVERRIDE/swapped-in"; APPLY_RC=100; APPLY_OUT="$LISTGAP"
runit; a_nocard apply-failed; a_exit0
grep -q "apply failed rc=100: E: Could not open file" "$WORK/stderr" 2>/dev/null && ok || bad "apt's error line must reach the journal"

# 51. a real apply failure pages with apt's error on the card.
t "apply-real-failure-pages-with-apt-error"
aged_somelib; APPLY_RC=100; APPLY_OUT='E: Sub-process /usr/bin/dpkg returned an error code (1)'
runit; a_card_sev apply-failed critical
grep -q "^apply-failed|.*rc=100 (E: Sub-process /usr/bin/dpkg" "$CARDS" 2>/dev/null && ok || bad "the card must carry apt's error line"

# 52. a clean run ends the collision streak.
t "clean-run-clears-collision-streak"
aged_somelib; printf '2\n' > "$COLLIDES"
runit; a_applied somelib
[ -f "$COLLIDES" ] && bad "a clean apply must clear the collision streak" || ok

# 52b. only the exact value 0 arms the writes. "true", "yes", "false", an empty value and a
#      value with a comment after it all stay in dry-run, and the journal says why.
t "dryrun-only-exact-zero-installs"
for v in true yes false "" "0 # live"; do
  aged_somelib; DRY="$v"
  runit; a_not_applied somelib; a_exit0
  grep -qF "HOSTSEC_APPLY_DRYRUN='$v' is not 0 or 1; staying in dry-run" "$WORK/stderr" 2>/dev/null \
    && ok || bad "DRYRUN='$v': expected the not-0-or-1 log line (got: $(tr '\n' ' ' <"$WORK/stderr"))"
  grep -q "DRYRUN: would apply: somelib" "$WORK/stderr" 2>/dev/null && ok || bad "DRYRUN='$v': expected a would-apply log"
done
aged_somelib; DRY=1
runit; a_not_applied somelib
grep -q "is not 0 or 1" "$WORK/stderr" 2>/dev/null && bad "DRYRUN=1 is a valid value, no warning" || ok
aged_somelib; DRY=0
runit; a_applied somelib
grep -q "is not 0 or 1" "$WORK/stderr" 2>/dev/null && bad "DRYRUN=0 is a valid value, no warning" || ok

# 52c. the master switch: only 1 runs the applier. Any other value turns it off (its
#      holds are released, toward patched) and the journal says why.
t "enabled-not-one-is-off-and-logged"
aged_somelib; ENA=yes
printf 'oldheld\t1.0\tgated\t%s\n' $((NOW - 2*DAY)) > "$STATE/holds.apply.tsv"
runit; a_exit0; a_not_applied somelib; a_unheld oldheld
grep -qF "HOSTSEC_APPLY_ENABLED='yes' is not 0 or 1; treating it as 0 (off)" "$WORK/stderr" 2>/dev/null \
  && ok || bad "expected the not-0-or-1 log line for HOSTSEC_APPLY_ENABLED"

# 53. delivery: a card that was not delivered writes no throttle stamp, so the next run
#     sends it again (not 6 hours later); a delivered one is throttled; one over the
#     per-run cap goes on the next run. The stamp file is ev.apply-<event>.
t "signal-undelivered-retried"
setup "$(row libssl3 9.9 amd64 EvilPPA ppa.launchpad.net noble 0 0)"
: > "$WORK/report-fail"
runit; a_exit0; a_nocard apply-anom-libssl3
[ -f "$STATE/ev.apply-apply-anom-libssl3" ] && bad "an undelivered card must not be stamped" || ok
grep -q "post failed: apply-anom-libssl3" "$WORK/stderr" && ok || bad "the failed post must be logged"
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + 3600))"; runit; a_card_sev apply-anom-libssl3 warning
[ "$(cat "$STATE/ev.apply-apply-anom-libssl3" 2>/dev/null)" = "warning $((NOW + 3600))" ] && ok || bad "a delivered card is stamped with its send time"
: > "$CARDS"; RUN_NOW="$((NOW + 7200))"; runit; a_nocard apply-anom-libssl3

t "signal-over-cap-next-run"
setup "$(printf '%s\n%s' "$(row libssl3 9.9 amd64 EvilPPA ppa.launchpad.net noble 0 0)" "$(row libc6 9.9 amd64 EvilPPA ppa.launchpad.net noble 0 0)")"
MAXP=1
runit; n=$(grep -c '^apply-anom-' "$CARDS"); [ "$n" = 1 ] && ok || bad "the cap allows one card a run (got $n)"
grep -q "post cap hit; suppressed: apply-anom-" "$WORK/stderr" && ok || bad "the capped card must be logged"
RUN_NOW="$((NOW + 3600))"; runit
n=$(grep -c '^apply-anom-' "$CARDS"); [ "$n" = 2 ] && ok || bad "the next run sends only the capped card (got $n in two runs)"
a_card apply-anom-libssl3; a_card apply-anom-libc6
: > "$CARDS"; RUN_NOW="$((NOW + 7200))"; runit; a_nocard apply-anom-

# ===========================================================================
echo ""
echo "apply-aged-upgrades: $PASS passed, $FAIL failed"
rm -rf "$WORK" 2>/dev/null || :
[ "$FAIL" -eq 0 ]
