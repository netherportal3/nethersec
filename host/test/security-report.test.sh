#!/usr/bin/env sh
# security-report.test.sh: offline behavioral harness for the READ-ONLY host
# security detector. Mocks apt-get / journalctl / the CVE-severity lookup / the
# report transport via the script's env seams, and asserts the pending-security
# alerting REWORK without a real box or a network:
#   - SILENT while pending within grace
#   - the grace is PER PACKAGE: a package joining a non-empty pending set does NOT
#     inherit the set's age (a "STUCK 38h" page for a fix pending 6h), the old
#     single-line clock migrates without losing an in-progress stuck page (also when a
#     stale table disagrees with it), malformed state never crashes, and an unreadable
#     apt run (or a failed clock read, NOW=0) never touches either state file
#   - each package keeps its OWN High/Critical grade: a lookup blip still pages for a
#     stuck, earlier-graded package whatever else joined, and an APPLIED package's
#     grade never comes back with its successor version
#   - a package that drops out for a run or two and returns at the SAME version resumes
#     its clock; a new version, or a return after the window, starts fresh
#   - a quiet "done" note on clear, ONLY for a High/Critical episode
#   - a critical PAGE only for a STUCK-past-grace High/Critical CVE
#   - the stuck-page keys off the CURRENT pending set, not a vanished-but-remembered High
#   - the candidate VERSION is parsed from NEW-INSTALL lines too (no [old] bracket)
#   - a stuck batch that is only low/medium raises ONE quiet non-paging card
#   - an undeterminable severity folds to monitor-unreadable (never a false page)
#   - the CVE lookup is NOT invoked when nothing is pending
#   - the applier backstop pages critical when the write-side applier is dead/stuck
#   - check 6 cards a world-writable path to the root-run scripts, sticky dirs aside
#   - check 2 cards a pending reboot ONLY for a High/Critical fix that is not live
#     (Livepatch fixes for the running kernel, needrestart for the rest), never on a
#     lookup error, and feeds the weekly summary with a throttled `reboot-pending` report
#   - a kernel newer than the running one counts as a pending reboot with no flag (Livepatch
#     suppresses it), is graded from the running version, and is a card anyway once it
#     has gone ungraded for 3 days
#   - checks 9-12 (box drift) card Livepatch off, the IP-options drop off, sshd taking
#     passwords and a listener outside the allowlist once each, resolve once fixed, and
#     fold a failed read into monitor-unreadable without touching an open card
#   - check 13 sends each published container's SOURCE packages (dpkg, distroless
#     status.d, apk origins) as a throttled `container-packages` report, resolves a gone
#     one, holds the first lists for the arm delay, and folds a failed `docker ps` into
#     monitor-unreadable
#
#   sh host/test/security-report.test.sh
#
# Exit 0 = all asserts passed.
set -u
# Built at runtime so this file stays free of the character it checks for.
EMDASH=$(printf '\342\200\224')

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../security-report.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/srt.$$"); mkdir -p "$WORK"
BIN="$WORK/bin"; STATE="$WORK/state"; mkdir -p "$BIN" "$STATE"
# Check 6 walks up from the scripts' directory, so the runs point it at a fixture
# install dir with known modes (the real one's depend on where the harness runs).
SP_ROOT="$WORK/sp/opt"; SP_DIR="$SP_ROOT/nethersec"; mkdir -p "$SP_DIR"
: > "$SP_DIR/security-report.sh"; : > "$SP_DIR/nethersec-report.sh"
chmod 0755 "$WORK" "$WORK/sp"
# It walks on up to /, so a world-writable non-sticky directory above $WORK would
# card in every run below. Say so once instead of failing dozens of asserts.
sp_d="$WORK"
while [ "$sp_d" != "/" ]; do
  sp_d=$(dirname -- "$sp_d")
  if [ -n "$(find "$sp_d" -maxdepth 0 -type d -perm -0002 ! -perm -1000 2>/dev/null)" ]; then
    echo "security-report.test: $sp_d is world-writable without the sticky bit; set TMPDIR to a safe directory"
    rm -rf "$WORK"; exit 2
  fi
done
CARDS="$WORK/cards.log"
NOW=1788000000
DAY=86400
GRACE=93600          # 26h default
PASS=0; FAIL=0; CUR=""

# --- mocks -----------------------------------------------------------------
# apt-get: `command -v` just needs it executable; `-s dist-upgrade` prints the
# canned simulation ($MOCK_SIM_FILE). Real apt output is never empty (boilerplate),
# so an empty file would (correctly) read as apt-unreadable; SIM files carry
# boilerplate + optional `Inst` lines.
cat > "$BIN/apt-get" <<'EOF'
#!/bin/sh
case " $* " in *" -s "*) [ -n "${MOCK_SIM_FILE:-}" ] && [ -f "$MOCK_SIM_FILE" ] && cat "$MOCK_SIM_FILE"; exit 0 ;; esac
exit 0
EOF
# journalctl: present + empty, so the SSH/log checks are READABLE (not unreadable)
# and simply baseline; they never contribute a card here.
cat > "$BIN/journalctl" <<'EOF'
#!/bin/sh
exit 0
EOF
# report transport: record event|state|severity|detail so we can assert paging vs
# quiet AND the detail contents (e.g. the bare CVE link).
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
# every attempt is noted, delivered or not
printf '%s|%s\n' "$ev" "$st" >> "${MOCK_DIR:-/nonexistent}/attempts" 2>/dev/null
# a hub that refuses the data events for this key, like one with a dm= key: HTTP 403,
# which nethersec-report.sh answers with exit 4
case "$ev" in
  reboot-pending|container-packages) [ -f "${MOCK_DIR:-/nonexistent}/report-refused" ] && exit 4 ;;
esac
# no answer at all (exit 3, like curl with no network), or an error answer (exit 1):
# nothing is delivered (and nothing recorded)
[ -f "${MOCK_DIR:-/nonexistent}/report-down" ] && exit 3
[ -f "${MOCK_DIR:-/nonexistent}/report-fail" ] && exit 1
printf 'E=%s|S=%s|V=%s|D=%s\n' "$ev" "$st" "$sv" "$dt" >> "$MOCK_CARDS"
exit 0
EOF
# version-aware CVE mock: emits <name>\thigh\t... for each stdin line whose VERSION
# equals $EXPECT_VER, else <name>\tunknown\t\t. Proves the detector parsed + forwarded
# the EXACT candidate version (the new-install version-parse guard).
cat > "$BIN/cve-byver" <<'EOF'
#!/bin/sh
TAB=$(printf '\t')
while IFS="$TAB" read -r name ver rest; do
  [ -n "$name" ] || continue
  if [ "$ver" = "${EXPECT_VER:-}" ]; then
    printf '%s\thigh\tCVE-NEW\thttps://ubuntu.com/security/CVE-NEW\n' "$name"
  else
    printf '%s\tunknown\t\t\n' "$name"
  fi
done
EOF
# sentinel CVE mock (the default): touch a sentinel so a test can prove the lookup
# WAS or was NOT invoked, then behave like `cat $CVEFILE`.
cat > "$BIN/cve-sentinel" <<EOF
#!/bin/sh
touch "$WORK/cve-invoked"
cat "$WORK/cve.empty" 2>/dev/null || true
EOF
# reboot check mocks (check 2). dpkg-query: the version of an installed package from
# $MOCK_DPKG_FILE (name<TAB>version), nothing for any other. The list-mode CVE lookup:
# the row for each name from $MOCK_DIR/cvelist.rows (5 columns), nothing for a name with
# no row; it notes that it ran, in which mode, and what it was asked. Livepatch and
# needrestart print their fixture, or fail when there is none.
cat > "$BIN/mock-dpkg-query" <<'EOF'
#!/bin/sh
for a in "$@"; do p="$a"; done
[ -f "${MOCK_DPKG_FILE:-}" ] || exit 1
case "$*" in
  *'${Package}'*)   # a listing: every installed name the glob matches
    found=0
    while IFS="$(printf '\t')" read -r n v; do
      # shellcheck disable=SC2254
      case "$n" in $p) printf 'ii \t%s\t%s\n' "$n" "$v"; found=1 ;; esac
    done < "$MOCK_DPKG_FILE"
    [ "$found" = 1 ] || { echo "dpkg-query: no packages found matching $p" >&2; exit 1; }
    exit 0 ;;
esac
v=$(awk -F'\t' -v n="$p" '$1 == n { print $2; exit }' "$MOCK_DPKG_FILE")
[ -n "$v" ] || { echo "dpkg-query: no packages found matching $p" >&2; exit 1; }
printf 'ii \t%s\n' "$v"
EOF
cat > "$BIN/cve-list" <<'EOF'
#!/bin/sh
touch "$MOCK_DIR/cvelist-invoked"
[ "${HOSTSEC_CVE_LIST:-}" = "1" ] && touch "$MOCK_DIR/cvelist-mode"
TAB=$(printf '\t')
while IFS="$TAB" read -r name ver rest; do
  [ -n "$name" ] || continue
  printf '%s=%s%s\n' "$name" "$ver" "${rest:+|$rest}" >> "$MOCK_DIR/cvelist-seen"
  awk -F'\t' -v n="$name" '$1 == n { print; exit }' "$MOCK_DIR/cvelist.rows" 2>/dev/null
done
EOF
cat > "$BIN/mock-livepatch" <<'EOF'
#!/bin/sh
echo x >> "$MOCK_DIR/lp-calls"
# MOCK_LP_SANDBOXED=1: refused like a snap under the unit's NoNewPrivileges
[ "${MOCK_LP_SANDBOXED:-}" = 1 ] && { echo "cannot change profile for the next exec call: Operation not permitted" >&2; exit 1; }
[ -f "${MOCK_LP_FILE:-}" ] || exit 1
cat "$MOCK_LP_FILE"
EOF
# systemd-run: notes its arguments, drops its options and runs the command outside the
# "sandbox"; fails when $MOCK_DIR/srun-fail exists.
cat > "$BIN/mock-systemd-run" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" > "$MOCK_DIR/srun-args"
[ -f "$MOCK_DIR/srun-fail" ] && exit 1
while [ $# -gt 0 ]; do
  case "$1" in -p) shift 2 ;; -*) shift ;; *) break ;; esac
done
MOCK_LP_SANDBOXED="" exec "$@"
EOF
cat > "$BIN/mock-needrestart" <<'EOF'
#!/bin/sh
[ -f "${MOCK_NR_FILE:-}" ] || exit 1
cat "$MOCK_NR_FILE"
EOF
# apt-introspect.py (check 7): prints $MOCK_INTRO_FILE (its 9-column rows), or fails
# like a missing python3-apt when $MOCK_DIR/intro-fail exists.
cat > "$BIN/mock-introspect" <<'EOF'
#!/bin/sh
[ -f "${MOCK_DIR:-/nonexistent}/intro-fail" ] && exit 3
[ -f "${MOCK_INTRO_FILE:-}" ] && cat "$MOCK_INTRO_FILE"
exit 0
EOF
# docker (checks 8 and 13): `info -f {{.LiveRestoreEnabled}}` prints $MOCK_DIR/docker-lr;
# everything fails like a stopped daemon when $MOCK_DIR/docker-fail exists. Runs use a
# missing path by default (no Docker), so no other test depends on the runner's own
# Docker. Check 13 reads the fixture tree $MOCK_DIR/ctr: `ps` prints ctr/ps (none when
# absent, fails when ctr/ps-fail exists), `inspect <id>` prints ctr/<id>/inspect,
# `image inspect <iid>` prints ctr/created-<iid>, and `cp -L <id>:<path> -` streams
# ctr/<id>/root<path> as a tar archive (logged to ctr/cp.log), failing when absent.
cat > "$BIN/mock-docker" <<'EOF'
#!/bin/sh
[ -f "${MOCK_DIR:-/nonexistent}/docker-fail" ] && exit 1
C="$MOCK_DIR/ctr"
last=""; for a in "$@"; do last="$a"; done
case "$1" in
  info) cat "$MOCK_DIR/docker-lr" ;;
  ps) [ -f "$C/ps-fail" ] && exit 1; [ -f "$C/ps" ] && cat "$C/ps"; exit 0 ;;
  inspect) [ -f "$C/$last/inspect" ] || exit 1; cat "$C/$last/inspect" ;;
  image) [ -f "$C/created-${last#sha256:}" ] || exit 1; cat "$C/created-${last#sha256:}" ;;
  cp)
    src=""; for a in "$@"; do case "$a" in *:/*) src="$a" ;; esac; done
    id="${src%%:*}"; path="${src#*:}"
    printf '%s %s\n' "$id" "$path" >> "$C/cp.log"
    f="$C/$id/root$path"
    [ -e "$f" ] || { echo "Error: Could not find the file $path in container $id" >&2; exit 1; }
    tar -cf - -C "$(dirname "$f")" "$(basename "$f")" ;;
  *) exit 0 ;;
esac
EOF
# ipv4-options-drop.sh --check (check 10): prints $MOCK_DIR/ipopt.out, exits with the
# code in $MOCK_DIR/ipopt.rc (0 when there is none), and notes its arguments.
cat > "$BIN/mock-ipopt" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" > "$MOCK_DIR/ipopt-args"
[ -f "$MOCK_DIR/ipopt.out" ] && cat "$MOCK_DIR/ipopt.out"
exit "$(cat "$MOCK_DIR/ipopt.rc" 2>/dev/null || echo 0)"
EOF
# sshd -T / -G (check 11): prints $MOCK_DIR/sshd.out, or fails like sshd with no host keys
# when $MOCK_DIR/sshd-fail exists. With $MOCK_DIR/sshd-T-fail only -T fails, like a
# socket-activated sshd that has no /run/sshd yet.
cat > "$BIN/mock-sshd" <<'EOF'
#!/bin/sh
case "${1:-}" in -T|-G) ;; *) exit 2 ;; esac
[ -f "$MOCK_DIR/sshd-fail" ] && { echo "sshd: no hostkeys available -- exiting." >&2; exit 1; }
[ "$1" = "-T" ] && [ -f "$MOCK_DIR/sshd-T-fail" ] && { echo "Missing privilege separation directory: /run/sshd" >&2; exit 255; }
cat "$MOCK_DIR/sshd.out"
EOF
# ss (check 12): notes its arguments, prints $MOCK_DIR/ss.out, or fails when
# $MOCK_DIR/ss-fail exists.
cat > "$BIN/mock-ss" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" > "$MOCK_DIR/ss-args"
[ -f "$MOCK_DIR/ss-fail" ] && exit 1
cat "$MOCK_DIR/ss.out"
EOF
chmod +x "$BIN"/apt-get "$BIN"/journalctl "$BIN"/mock-report "$BIN"/cve-byver "$BIN"/cve-sentinel \
  "$BIN"/mock-dpkg-query "$BIN"/cve-list "$BIN"/mock-livepatch "$BIN"/mock-systemd-run "$BIN"/mock-needrestart "$BIN"/mock-introspect \
  "$BIN"/mock-docker "$BIN"/mock-ipopt "$BIN"/mock-sshd "$BIN"/mock-ss

# build a SIM file: boilerplate + one UPGRADE `Inst` line per "pkg ver" arg pair.
mk_sim() { # file  [name ver]...
  f="$1"; shift
  {
    echo "Reading package lists..."
    echo "Building dependency tree..."
    echo "Calculating upgrade..."
    while [ $# -ge 2 ]; do
      printf 'Inst %s [%s-old] (%s Ubuntu:24.04/noble-security [amd64])\n' "$1" "$2" "$2"
      shift 2
    done
    echo "0 upgraded, 0 newly installed, 0 to remove."
  } > "$f"
}

setup() {
  rm -rf "$STATE"; mkdir -p "$STATE"
  chmod 0755 "$SP_ROOT" "$SP_DIR"
  chmod 0644 "$SP_DIR/security-report.sh" "$SP_DIR/nethersec-report.sh"
  : > "$CARDS"
  rm -f "$WORK/cve-invoked"
  SIMFILE="$WORK/sim.empty"; mk_sim "$SIMFILE"        # default: nothing pending
  CVEFILE="$WORK/cve.empty"; : > "$CVEFILE"           # default: lookup returns nothing
  CVE_LOOKUP=1; REBOOT="$WORK/noreboot"; RUN_NOW="$NOW"
  CVECMD="$BIN/cve-sentinel"                          # default lookup (sentinel + cat CVEFILE)
  XRE=""                                              # HOSTSEC_SECURITY_ORIGIN_RE (off)
  # reboot check: no Livepatch and no needrestart unless a test adds them
  rm -f "$WORK"/cvelist-* "$WORK/report-fail" "$WORK/report-down" "$WORK/report-refused" "$WORK/attempts"
  MAXP=8                                              # HOSTSEC_MAX_POSTS
  DPKGFILE="$WORK/dpkg.tsv"; : > "$DPKGFILE"
  CVEROWS="$WORK/cvelist.rows"; : > "$CVEROWS"
  LPFILE="$WORK/lp.json"; rm -f "$LPFILE"; LPCMD="$WORK/no-livepatch"
  LPSANDBOX=""; SRUNCMD="$WORK/no-systemd-run"; rm -f "$WORK"/srun-*   # no unit sandbox, no systemd-run
  NRFILE="$WORK/nr.out"; rm -f "$NRFILE"; NRCMD="$WORK/no-needrestart"
  ARM=0                                               # HOSTSEC_REBOOT_REPORT_ARM_SECS
  KREL="6.8.0-59-generic"                            # HOSTSEC_KERNEL_RELEASE (no package owns it unless a test adds one)
  DPKGINFO="$WORK/dpkginfo"; rm -rf "$DPKGINFO"; mkdir -p "$DPKGINFO"
  INTROFILE="$WORK/intro.tsv"; : > "$INTROFILE"; rm -f "$WORK/intro-fail"   # check 7: nothing pending
  TP_ENABLE=1; TP_IGNORE=""
  DOCKERCMD="$WORK/no-docker"; LR_ENABLE=1; rm -f "$WORK/docker-fail"; echo true > "$WORK/docker-lr"   # check 8: no Docker
  # checks 9-12: not Ubuntu (so Livepatch and the IP-options drop are off), no sshd,
  # no listener allowlist
  OSREL="$WORK/os-release"; rm -f "$OSREL" "$WORK/lp-calls"; LP_CHECK=auto; IPOPT_CHECK=auto
  IPOPTCMD="$BIN/mock-ipopt"; rm -f "$WORK"/ipopt.* "$WORK/ipopt-args"
  SSHDCMD="$WORK/no-sshd"; SSHD_CHECK=1; rm -f "$WORK/sshd.out" "$WORK/sshd-fail" "$WORK/sshd-T-fail"
  SSCMD="$BIN/mock-ss"; LISTEN_ALLOW=""; : > "$WORK/ss.out"; rm -f "$WORK/ss-fail" "$WORK/ss-args"
  rm -rf "$WORK/ctr"; mkdir -p "$WORK/ctr"; CP_ENABLE=1; CP_ARM=0; CP_MAX=12             # check 13: no containers
}
runit() {
  env \
    HOSTSEC_KILL_FILE="$WORK/nokill" \
    HOSTSEC_SOURCE=testbox \
    HOSTSEC_REPORT_SCRIPT="$BIN/mock-report" \
    HOSTSEC_STATE_DIR="$STATE" \
    HOSTSEC_APT_GET="$BIN/apt-get" \
    HOSTSEC_NOW="$RUN_NOW" \
    HOSTSEC_SECUPDATE_GRACE_SECS="$GRACE" \
    HOSTSEC_CVE_LOOKUP="$CVE_LOOKUP" \
    HOSTSEC_CVE_CMD="$CVECMD" \
    HOSTSEC_SECURITY_ORIGIN_RE="$XRE" \
    HOSTSEC_APPLY_KILL_FILE="$WORK/noapplykill" \
    HOSTSEC_REBOOT_FILE="$REBOOT" \
    HOSTSEC_DPKG_QUERY="$BIN/mock-dpkg-query" \
    HOSTSEC_LIVEPATCH_CMD="$LPCMD" \
    HOSTSEC_SYSTEMD_RUN="$SRUNCMD" \
    HOSTSEC_APPLY_NEEDRESTART="$NRCMD" \
    HOSTSEC_REBOOT_REPORT_ARM_SECS="$ARM" \
    HOSTSEC_KERNEL_RELEASE="$KREL" \
    HOSTSEC_DPKG_INFO_DIR="$DPKGINFO" \
    HOSTSEC_LOGERR_ENABLE=0 \
    HOSTSEC_SCRIPT_PATH="$SP_DIR" \
    HOSTSEC_INTROSPECT_CMD="$BIN/mock-introspect" \
    HOSTSEC_THIRDPARTY_ENABLE="$TP_ENABLE" \
    HOSTSEC_THIRDPARTY_IGNORE="$TP_IGNORE" \
    HOSTSEC_DOCKER_CMD="$DOCKERCMD" \
    HOSTSEC_LIVE_RESTORE_ENABLE="$LR_ENABLE" \
    HOSTSEC_OS_RELEASE="$OSREL" \
    HOSTSEC_LIVEPATCH_CHECK="$LP_CHECK" \
    HOSTSEC_IPOPT_CHECK="$IPOPT_CHECK" \
    HOSTSEC_IPOPT_CMD="$IPOPTCMD" \
    HOSTSEC_SSHD_CHECK="$SSHD_CHECK" \
    HOSTSEC_SSHD_CMD="$SSHDCMD" \
    HOSTSEC_LISTEN_ALLOW="$LISTEN_ALLOW" \
    HOSTSEC_SS_CMD="$SSCMD" \
    HOSTSEC_CTRPKG_ENABLE="$CP_ENABLE" \
    HOSTSEC_CTRPKG_ARM_SECS="$CP_ARM" \
    HOSTSEC_CTRPKG_MAX_POSTS="$CP_MAX" \
    HOSTSEC_MAX_POSTS="$MAXP" \
    NETHERSEC_REPORT_URL="http://x/report" NETHERSEC_REPORT_KEY="y" \
    MOCK_SIM_FILE="$SIMFILE" MOCK_CARDS="$CARDS" MOCK_DIR="$WORK" \
    MOCK_INTRO_FILE="$INTROFILE" \
    MOCK_DPKG_FILE="$DPKGFILE" MOCK_LP_FILE="$LPFILE" MOCK_LP_SANDBOXED="$LPSANDBOX" MOCK_NR_FILE="$NRFILE" \
    PATH="$BIN:$PATH" \
    sh "$SCRIPT" 2>"$WORK/stderr"
  RC=$?
}

# --- assertions ------------------------------------------------------------
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; }
a_exit0()        { [ "$RC" = 0 ] && ok || bad "expected exit 0, got $RC"; }
a_no_cards()     { [ -s "$CARDS" ] && bad "expected NO cards, got: $(tr '\n' ' ' <"$CARDS")" || ok; }
a_card()         { grep -q "E=$1|" "$CARDS" 2>/dev/null && ok || bad "expected a card for event '$1' (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_no_card()      { grep -q "E=$1|" "$CARDS" 2>/dev/null && bad "unexpected card for '$1'" || ok; }
a_card_sev()     { grep -q "E=$1|S=[^|]*|V=$2" "$CARDS" 2>/dev/null && ok || bad "expected '$1' at severity '$2' (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_card_state()   { grep -q "E=$1|S=$2|" "$CARDS" 2>/dev/null && ok || bad "expected '$1' state '$2' (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_detail_has()   { d=$(grep "E=$1|" "$CARDS" 2>/dev/null | sed 's/.*|D=//'); printf '%s' "$d" | grep -qF "$2" && ok || bad "expected '$1' detail to contain '$2' (got: $d)"; }
a_detail_lacks() { d=$(grep "E=$1|" "$CARDS" 2>/dev/null | sed 's/.*|D=//'); printf '%s' "$d" | grep -qF "$2" && bad "'$1' detail must NOT contain '$2' (got: $d)" || ok; }
a_lookup_ran()   { [ -f "$WORK/cve-invoked" ] && ok || bad "expected the CVE lookup to be invoked"; }
a_lookup_norun() { [ -f "$WORK/cve-invoked" ] && bad "CVE lookup must NOT run" || ok; }
a_clock_gone()   { [ -f "$STATE/pending-since.security-updates" ] && bad "expected pending-since clock removed" || ok; }
a_clock_has()    { grep -q "$1" "$STATE/pending-since.security-updates" 2>/dev/null && ok || bad "expected clock to contain '$1' (got: $(cat "$STATE/pending-since.security-updates" 2>/dev/null))"; }
# the episode file's field 1 (oldest CURRENT first-seen) must be exactly this epoch
a_since_is()     { s=""; read -r s _r < "$STATE/pending-since.security-updates" 2>/dev/null; [ "$s" = "$1" ] && ok || bad "expected episode start '$1' (got: '$s')"; }
# per-package table: name<TAB>first_seen<TAB>version<TAB>gone_since<TAB>prio<TAB>cve<TAB>link
# (gone_since 0 = pending now; > 0 = a tombstone kept for a short dropout window)
FIRST="$STATE/first-seen.security-updates.tsv"
TAB=$(printf '\t')
first_dump()     { cat "$FIRST" 2>/dev/null | tr '\t\n' ': '; }
a_first_has()    { awk -F'\t' -v n="$1" -v t="$2" '$1 == n && $2 == t && ($4 == "" || $4 == 0) { f = 1 } END { exit !f }' "$FIRST" 2>/dev/null \
                     && ok || bad "expected pending row '$1' first-seen $2 (got: $(first_dump))"; }
a_first_lacks()  { awk -F'\t' -v n="$1" '$1 == n && ($4 == "" || $4 == 0) { f = 1 } END { exit !f }' "$FIRST" 2>/dev/null \
                     && bad "'$1' must NOT be a pending row (got: $(first_dump))" || ok; }
a_tomb_has()     { awk -F'\t' -v n="$1" '$1 == n && $4 + 0 > 0 { f = 1 } END { exit !f }' "$FIRST" 2>/dev/null \
                     && ok || bad "expected a dropout tombstone for '$1' (got: $(first_dump))"; }
a_first_gone()   { [ -f "$FIRST" ] && bad "expected first-seen table removed" || ok; }
a_no_tmp()       { ls "$STATE" | grep -q '\.tmp\.' && bad "a state temp file was left behind: $(ls "$STATE")" || ok; }

cve_line() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" > "$CVEFILE"; }  # name result cve link
cve_add()  { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$CVEFILE"; } # append another row
seed_clock() { printf '%s\n' "$1" > "$STATE/pending-since.security-updates"; }  # raw line
seed_first() { : > "$FIRST"; while [ $# -ge 2 ]; do printf '%s\t%s\t-\t0\t-\t-\t-\n' "$1" "$2" >> "$FIRST"; shift 2; done; }  # [name epoch]... (pending, ungraded)
seed_row()   { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$FIRST"; }  # name first ver gone prio cve link
H=3600

# ===========================================================================
# 1. nothing pending, no prior episode -> completely silent; lookup NEVER invoked
t "clean-silent"
setup
runit; a_exit0; a_no_cards; a_lookup_norun

# 2. pending High, within grace -> SILENT, clock stamped with the priority
t "high-within-grace-silent"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
runit; a_no_cards; a_clock_has high

# 3. pending High, PAST grace -> critical PAGE; detail carries the BARE CVE url (never a
#    []() markdown link); lookup DID run
t "high-past-grace-critical"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
runit; a_card_sev security-updates critical
a_detail_has   security-updates 'https://ubuntu.com/security/CVE-2026-1'
a_detail_lacks security-updates ']('
a_lookup_ran

# 4. pending Medium, PAST grace -> ONE quiet non-paging card (u-u looks stopped), NOT a page
t "medium-past-grace-quiet-card"
setup
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib medium CVE-2026-2 https://ubuntu.com/security/CVE-2026-2
seed_clock "$((NOW - 100000)) 1  "
runit; a_card_sev security-updates warning; a_no_card monitor-unreadable

# 5. pending, lookup ERROR (empty output), PAST grace -> monitor-unreadable (quiet)
t "lookup-error-past-grace-unreadable"
setup
mk_sim "$SIMFILE" somelib 2.0
: > "$CVEFILE"   # lookup yields nothing -> fewer lines than pending -> error
seed_clock "$((NOW - 100000)) 1  "
runit; a_card monitor-unreadable; a_no_card security-updates

# 6. episode CLEARS with a High seen -> quiet "done" note (resolved), clock removed; the
#    done detail carries the bare CVE link (and never the pkg name bleeding into it)
t "clear-high-done-note"
setup
seed_clock "$((NOW - 5000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
runit; a_card_state security-updates-applied triggered; a_card_sev security-updates-applied info; a_clock_gone
a_detail_has   security-updates-applied 'https://ubuntu.com/security/CVE-2026-1'
a_detail_lacks security-updates-applied 'openssh-server'

# 7. episode clears with only Medium (no stored priority) -> NO done note
t "clear-medium-no-done"
setup
seed_clock "$((NOW - 5000)) 1  "
runit; a_no_card security-updates-applied; a_clock_gone

# 8. CVE gate DISABLED, pending past grace -> quiet WARNING card (never silent, never page)
t "gate-disabled-warning"
setup
mk_sim "$SIMFILE" somelib 2.0
CVE_LOOKUP=0
seed_clock "$((NOW - 100000)) 1  "
runit; a_card_sev security-updates warning

# 9. episode-MAX memory: stored High + its pkg STILL pending, but THIS run's lookup errors
#    (a blip), past grace -> still a critical page (the exact pkg is confirmed still pending)
t "stored-high-lookup-blip-still-critical"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
: > "$CVEFILE"   # this run's lookup fails
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
runit; a_card_sev security-updates critical

# 10. Critical outranks High in the pending set -> critical
t "critical-outranks-high"
setup
mk_sim "$SIMFILE" pkga 1.0 pkgb 2.0
printf 'pkga\thigh\tCVE-A\thttps://ubuntu.com/security/CVE-A\npkgb\tcritical\tCVE-B\thttps://ubuntu.com/security/CVE-B\n' > "$CVEFILE"
seed_clock "$((NOW - 100000)) 2  "
runit; a_card_sev security-updates critical

# 11. backward-compat: OLD single-token clock file on clear -> no crash, no done
t "legacy-clock-clear"
setup
seed_clock "$((NOW - 5000))"
runit; a_exit0; a_no_card security-updates-applied; a_clock_gone

# 12. a staged reboot with nothing High/Critical raises no card at all (the reboot
#     check's own cases are at the end)
t "reboot-flag-alone-no-card"
setup
REBOOT="$WORK/reboot-required"; : > "$REBOOT"; printf 'somelib\n' > "$REBOOT.pkgs"
printf 'somelib\t2.0\n' > "$DPKGFILE"; CVECMD="$BIN/cve-list"
printf 'somelib\tmedium\tCVE-2026-2\thttps://ubuntu.com/security/CVE-2026-2\t\n' > "$CVEROWS"
runit; a_exit0; a_no_card reboot-security

# 13. High within grace does NOT page, then the SAME episode past grace DOES page
t "grace-boundary-two-runs"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
RUN_NOW="$NOW"; runit; a_no_cards           # run 1: within grace, silent (clock stamped)
: > "$CARDS"
RUN_NOW="$((NOW + 100000))"; runit          # run 2: same clock, now past grace
a_card_sev security-updates critical

# 14. NEW-INSTALL Inst line (no [old] bracket; a versioned kernel image / soname bump)
#     must still parse the candidate VERSION from the (…) field, not the origin. A
#     version-aware mock pages ONLY if the EXACT new version reached it.
t "newinstall-version-parsed"
setup
SIMFILE="$WORK/sim_newinstall"
{ echo "Reading package lists..."
  echo "Building dependency tree..."
  echo "Inst linux-image-6.8.0-52-generic (6.8.0-52 Ubuntu:24.04/noble-security [amd64])"
  echo "0 upgraded, 1 newly installed, 0 to remove."; } > "$SIMFILE"
CVECMD="env EXPECT_VER=6.8.0-52 $BIN/cve-byver"
seed_clock "$((NOW - 100000)) 1  "
runit; a_card_sev security-updates critical

# 15. after the High pkg is APPLIED (gone from the pending set) but a low/medium pkg keeps
#     the episode alive, do NOT keep paging for the vanished High (episode-MAX must not
#     resurrect it). The remaining low/med raises the quiet card, naming no stale CVE.
t "applied-high-lowmed-lingers-no-page"
setup
mk_sim "$SIMFILE" somelib 2.0                 # only the low pkg is still pending now
cve_line somelib medium CVE-LOW https://ubuntu.com/security/CVE-LOW
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
runit; a_card_sev security-updates warning
a_detail_lacks security-updates 'CVE-2026-1'

# 16. lookup RETURNS a full 'error' line (not empty) past grace -> monitor-unreadable
#     (the error-token path, distinct from the short-output path exercised by test 5)
t "lookup-error-token-unreadable"
setup
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib error "" ""
seed_clock "$((NOW - 100000)) 1  "
runit; a_card monitor-unreadable; a_no_card security-updates

# 17. applier backstop: a stale apply-heartbeat (dead-man's switch) pages critical
t "backstop-heartbeat-stale-critical"
setup
printf '%s\n' "$((NOW - 4*3600))" > "$STATE/apply-heartbeat"   # 4h stale (>= 3h ceiling)
runit; a_card_sev apply-backstop critical

# 18. applier backstop: a release-age hold stuck past the ceiling pages critical
t "backstop-hold-stuck-critical"
setup
printf '%s\n' "$NOW" > "$STATE/apply-heartbeat"                # fresh heartbeat (so (a) is quiet)
printf 'stuckpkg\t2.0\tgated\t%s\n' "$((NOW - 20*DAY))" > "$STATE/holds.apply.tsv"
runit; a_card_sev apply-backstop critical

# 19. stored High with EMPTY cve+link (a graded High whose CVE id was rejected by the
#     helper) + that pkg STILL pending + this run's lookup blips -> the blip-defense must
#     STILL page. Guards the clock round-trip: the empty optional fields must not shift the
#     load-bearing pkg name out of its slot (which would silently lose cs_wpkg).
t "stored-high-empty-cve-blip-still-critical"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
: > "$CVEFILE"   # this run's lookup blips (empty)
seed_clock "$((NOW - 100000)) 1 high openssh-server"   # prio + pkg, EMPTY cve+link (trailing)
runit; a_card_sev security-updates critical

# --- per-package grace ---------------------------------------------------------
# With ONE episode clock that reset only when the pending set went EMPTY, a package
# joining a non-empty set would inherit the set's age: a curl/sudo batch starts the
# clock, u-u applies it, linux-libc-dev joins ~20h later in the same (never-empty) set,
# and the page says "STUCK 38h" for a fix pending ~6h. Each package runs its own
# first-seen clock.

# 20. inherited-age regression, multi-run: batch A (low) pending from T0; at T0+20h A clears
#     and B (critical) appears in the SAME run (set never empty); at T0+38h B is still
#     pending -> NO page (B is 18h old); at B-first-seen + 26h -> page, detail shows B's age.
t "p2-joiner-does-not-inherit-episode-age"
setup
T0="$NOW"
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib low "" ""
RUN_NOW="$T0"; runit; a_no_cards; a_first_has somelib "$T0"
: > "$CARDS"
mk_sim "$SIMFILE" linux-libc-dev 7.0.0-14.14            # A applied, B joins, same run
cve_line linux-libc-dev critical CVE-2026-9 https://ubuntu.com/security/CVE-2026-9
RUN_NOW="$((T0 + 20*H))"; runit; a_no_cards
a_first_has linux-libc-dev "$((T0 + 20*H))"; a_first_lacks somelib
a_since_is "$((T0 + 20*H))"                             # episode start follows the CURRENT set
a_clock_has critical                                    # episode memory still graded it
: > "$CARDS"
RUN_NOW="$((T0 + 38*H))"; runit                         # B is only 18h old here
a_no_card security-updates; a_no_card monitor-unreadable
a_first_has linux-libc-dev "$((T0 + 20*H))"             # B's clock carried, not restarted
: > "$CARDS"
RUN_NOW="$((T0 + 20*H + GRACE))"; runit                 # B's OWN grace is up -> page
a_card_sev security-updates critical
a_detail_has   security-updates 'STUCK 26h'
a_detail_has   security-updates 'linux-libc-dev (pending 26h)'
a_detail_has   security-updates 'https://ubuntu.com/security/CVE-2026-9'
a_detail_lacks security-updates '46h'                   # T0's age must not leak in
a_no_tmp

# 21. an older low/medium package that IS stuck keeps the quiet card, but a critical that
#     joined later must NOT page on the old package's clock; it pages once ITS grace is up.
t "p2-late-critical-waits-its-own-grace"
setup
T0="$NOW"
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib low "" ""
RUN_NOW="$T0"; runit; a_no_cards
mk_sim "$SIMFILE" somelib 2.0 linux-libc-dev 7.0.0-14.14
cve_line somelib low "" ""
cve_add  linux-libc-dev critical CVE-2026-9 https://ubuntu.com/security/CVE-2026-9
RUN_NOW="$((T0 + 20*H))"; runit; a_no_cards
: > "$CARDS"
RUN_NOW="$((T0 + 27*H))"; runit                         # somelib stuck 27h, libc-dev only 7h
a_card_sev security-updates warning
grep -q 'E=security-updates|S=triggered|V=critical' "$CARDS" && bad "late critical paged on the old clock" || ok
a_detail_has   security-updates '1 pending security update(s) STUCK 27h'   # counts the STUCK ones only
a_detail_has   security-updates 'somelib'
# the quiet card must not read as "no High/Critical pending" while one is in its window
a_detail_has   security-updates '(none of the stuck ones High/Critical)'
a_detail_has   security-updates '+1 newer incl. 1 High/Critical, still within the auto-apply window'
a_detail_lacks security-updates 'CVE-2026-9'
: > "$CARDS"
RUN_NOW="$((T0 + 20*H + GRACE))"; runit                 # libc-dev's own grace is up -> page
a_card_sev security-updates critical
a_detail_has security-updates 'STUCK 46h'              # oldest stuck (somelib)
a_detail_has security-updates 'linux-libc-dev (pending 26h)'   # the paging pkg's OWN age

# 22. quiet: a low/medium package continuously pending >= grace still raises the quiet card
#     (multi-run, clocks stamped by the detector itself, no seeding)
t "quiet-continuous-medium-card"
setup
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib medium CVE-2026-2 https://ubuntu.com/security/CVE-2026-2
RUN_NOW="$NOW"; runit; a_no_cards
: > "$CARDS"
RUN_NOW="$((NOW + GRACE))"; runit
a_card_sev security-updates warning; a_no_card monitor-unreadable
a_detail_has security-updates 'STUCK 26h'

# 23. quiet: continuously pending >= grace with the lookup DOWN -> monitor-unreadable, never
#     dropped and never a page (multi-run)
t "quiet-continuous-lookup-down-unreadable"
setup
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib medium "" ""
RUN_NOW="$NOW"; runit; a_no_cards
: > "$CARDS"; : > "$CVEFILE"                            # lookup now returns nothing
RUN_NOW="$((NOW + GRACE))"; runit
a_card monitor-unreadable; a_no_card security-updates
a_first_has somelib "$NOW"                              # clock kept running (apt read fine)

# 24. the done-note still keys off the EPISODE (set goes empty), not a package: A (high)
#     applied while B (low) lingers -> no note yet; B applied -> set empty -> ONE quiet done
#     note naming A's CVE; both clocks cleared
t "p3-done-note-on-episode-clear"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19 somelib 2.0
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
cve_add  somelib low "" ""
RUN_NOW="$NOW"; runit; a_no_cards
mk_sim "$SIMFILE" somelib 2.0                           # the High applied, low lingers
cve_line somelib low "" ""
RUN_NOW="$((NOW + H))"; runit; a_no_cards; a_first_lacks openssh-server
mk_sim "$SIMFILE"                                        # all applied
RUN_NOW="$((NOW + 2*H))"; runit
a_card_state security-updates-applied triggered; a_card_sev security-updates-applied info
a_detail_has security-updates-applied 'CVE-2026-1'
a_clock_gone; a_first_gone

# 25. migration: a box upgraded mid-episode has ONLY the old single-line clock (no
#     table). Its in-progress stuck page must survive the upgrade (pending pkgs are seeded
#     from the old start), and the table then takes over: a package joining AFTER the
#     migration run gets its own fresh clock, not the legacy start.
t "p4-legacy-clock-migrates"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
runit; a_card_sev security-updates critical
a_first_has openssh-server "$((NOW - 100000))"
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19 newlib 3.0
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
cve_add  newlib critical CVE-2026-7 https://ubuntu.com/security/CVE-2026-7
RUN_NOW="$((NOW + H))"; runit
a_first_has newlib "$((NOW + H))"                       # joiner: its own clock
a_first_has openssh-server "$((NOW - 100000))"          # migrated clock carried

# 26. once the table exists it WINS over the episode start; a package the table says
#     is fresh must not re-inherit an old field-1 start (the per-package fix must not regress)
t "p4-table-wins-over-episode-start"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
seed_first somelib "$((NOW - 100000))"                  # valid table, openssh not in it yet
runit; a_no_card security-updates
a_first_has openssh-server "$NOW"

# 27. a table that EXISTS but has no valid row (lost/garbled write) falls back to the
#     episode start; conservative, the stuck page is kept
t "p4-empty-table-falls-back"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
: > "$FIRST"
runit; a_card_sev security-updates critical

# 28. malformed state never crashes and never pages; garbage episode line + junk
#     table rows (no tab, non-numeric, zero epoch, empty name) are ignored; the pending
#     package starts fresh at NOW. A table stamp in the FUTURE (skewed RTC) is clamped.
t "p4-malformed-state-no-crash"
setup
mk_sim "$SIMFILE" somelib 2.0 otherlib 1.1
cve_line somelib high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
cve_add  otherlib low "" ""
seed_clock "garbage words here and more"
printf 'nonsense\nsomelib\tabc\n\t123\nsomelib\t0\notherlib\t%s\n' "$((NOW + 10*DAY))" > "$FIRST"
runit; a_exit0; a_no_cards
a_first_has somelib "$NOW"; a_first_has otherlib "$NOW"
a_since_is "$NOW"
t "p4-empty-state-files-no-crash"
setup
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib low "" ""
: > "$STATE/pending-since.security-updates"; : > "$FIRST"
runit; a_exit0; a_no_cards; a_first_has somelib "$NOW"

# 29. apt UNREADABLE never touches either clock (and folds into monitor-unreadable)
t "p5-unreadable-leaves-clocks"
setup
seed_clock "$((NOW - 5000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
seed_first openssh-server "$((NOW - 5000))"
SIMFILE="$WORK/sim.none"; : > "$SIMFILE"                # apt prints nothing -> unreadable
b1=$(cksum < "$STATE/pending-since.security-updates"); b2=$(cksum < "$FIRST")
RUN_NOW="$((NOW + 2*DAY))"; runit
a_card monitor-unreadable; a_no_card security-updates; a_no_card security-updates-applied
[ "$(cksum < "$STATE/pending-since.security-updates")" = "$b1" ] && ok || bad "episode clock changed on unreadable"
[ "$(cksum < "$FIRST")" = "$b2" ] && ok || bad "first-seen table changed on unreadable"

# 30. a lookup error on a package still WITHIN its grace does not turn a confirmed
#     low/medium stuck package into monitor-unreadable (only STUCK packages must be graded)
t "p6-within-grace-error-does-not-blind-stuck"
setup
mk_sim "$SIMFILE" somelib 2.0 freshlib 1.0
cve_line somelib medium "" ""
cve_add  freshlib error "" ""
seed_clock "$((NOW - 100000)) 2  "
seed_first somelib "$((NOW - 100000))" freshlib "$((NOW - 1000))"
runit; a_card_sev security-updates warning; a_no_card monitor-unreadable
a_detail_lacks security-updates 'freshlib'

# 31. the stored episode-max High is still pending but WITHIN its own grace; a lookup
#     blip must not page for it on another package's clock -> the stuck (ungraded) package
#     folds to monitor-unreadable instead
t "p6-stored-high-within-grace-no-blip-page"
setup
mk_sim "$SIMFILE" somelib 2.0 openssh-server 1:9.6p1-13.19
: > "$CVEFILE"                                          # this run's lookup blips
seed_clock "$((NOW - 100000)) 2 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
seed_first somelib "$((NOW - 100000))" openssh-server "$((NOW - 1000))"
runit; a_no_card security-updates; a_card monitor-unreadable

# 32. the stored High that IS itself stuck still pages through a lookup blip, even with
#     a fresh package alongside (the blip defense survives the per-package split: the
#     grade is stored in that package's own row)
t "p6-stored-high-stuck-blip-pages"
setup
mk_sim "$SIMFILE" somelib 2.0 openssh-server 1:9.6p1-13.19
: > "$CVEFILE"
seed_clock "$((NOW - 100000)) 2 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
: > "$FIRST"
seed_row somelib "$((NOW - 1000))" 2.0 0 - - -
seed_row openssh-server "$((NOW - 100000))" 1:9.6p1-13.19 0 high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
runit; a_card_sev security-updates critical
a_detail_has security-updates 'openssh-server (pending 27h)'
a_detail_has security-updates 'CVE-2026-1'

# 33. the blip defense is PER PACKAGE: a fresher Critical joining later must not overwrite
#     an older High's memory. openssh-server (High) pending from T0; newlib (Critical)
#     joins at T0+20h and becomes the episode max; from T0+26h the lookup is DOWN. The
#     High is stuck and was graded, so it pages at ITS grace, not 20h later at newlib's
#     (and never folds to the quiet monitor-unreadable).
t "p8-blip-defense-per-package"
setup
T0="$NOW"
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
RUN_NOW="$T0"; runit; a_no_cards
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19 newlib 3.0
cve_add  newlib critical CVE-2026-7 https://ubuntu.com/security/CVE-2026-7
RUN_NOW="$((T0 + 20*H))"; runit; a_no_cards
a_clock_has critical                                    # the episode max moved to newlib
: > "$CARDS"; : > "$CVEFILE"                            # the lookup is down from here on
RUN_NOW="$((T0 + GRACE))"; runit
a_card_sev security-updates critical
a_detail_has security-updates 'openssh-server (pending 26h)'
a_detail_has security-updates 'CVE-2026-1'
a_detail_has security-updates '+1 newer incl. 1 High/Critical'
a_no_card monitor-unreadable

# 34. a package that drops out of the pending set for a run or two (a resolver keep-back,
#     a mirror blip) and comes back at the SAME version was never applied: it resumes its
#     clock and grade instead of restarting a whole grace.
t "p9-dropout-same-version-resumes"
setup
T0="$NOW"
mk_sim "$SIMFILE" linux-libc-dev 7.0.0-14.14 somelib 2.0
cve_line linux-libc-dev critical CVE-2026-9 https://ubuntu.com/security/CVE-2026-9
cve_add  somelib low "" ""
RUN_NOW="$T0"; runit; a_no_cards
mk_sim "$SIMFILE" somelib 2.0                           # libc-dev hidden for one run
cve_line somelib low "" ""
RUN_NOW="$((T0 + 12*H))"; runit; a_no_cards
a_first_lacks linux-libc-dev; a_tomb_has linux-libc-dev
a_since_is "$T0"                                        # somelib still anchors the episode
mk_sim "$SIMFILE" linux-libc-dev 7.0.0-14.14 somelib 2.0   # back, SAME version
: > "$CVEFILE"                                          # and this run's lookup blips
RUN_NOW="$((T0 + 13*H))"; runit; a_no_cards
a_first_has linux-libc-dev "$T0"                        # clock resumed, not restarted
: > "$CARDS"
RUN_NOW="$((T0 + 27*H))"; runit                         # lookup still down: stored grade pages
a_card_sev security-updates critical
a_detail_has security-updates 'linux-libc-dev (pending 27h)'
a_detail_has security-updates 'CVE-2026-9'

# 35. ...but a tombstone only lasts the dropout window (6h): back at the same version after
#     it, the package starts a fresh clock.
t "p9-dropout-past-window-fresh"
setup
T0="$NOW"
mk_sim "$SIMFILE" linux-libc-dev 7.0.0-14.14 somelib 2.0
cve_line linux-libc-dev critical CVE-2026-9 https://ubuntu.com/security/CVE-2026-9
cve_add  somelib low "" ""
RUN_NOW="$T0"; runit
mk_sim "$SIMFILE" somelib 2.0
RUN_NOW="$((T0 + H))"; runit; a_tomb_has linux-libc-dev
RUN_NOW="$((T0 + 8*H))"; runit; a_first_lacks linux-libc-dev   # tombstone expired + pruned
awk -F'\t' '$1 == "linux-libc-dev" { f = 1 } END { exit !f }' "$FIRST" 2>/dev/null \
  && bad "an expired tombstone must be pruned (got: $(first_dump))" || ok
mk_sim "$SIMFILE" linux-libc-dev 7.0.0-14.14 somelib 2.0
RUN_NOW="$((T0 + 9*H))"; runit
a_first_has linux-libc-dev "$((T0 + 9*H))"

# 36. a High that was APPLIED does not come back with its successor. openssh-server
#     (High) is applied while somelib keeps the episode open; a NEW openssh-server version
#     fixing only a Medium arrives inside the dropout window. The new version gets its
#     own clock and grade, so when it is stuck the page does not cite the old, already
#     fixed CVE; neither with a fresh Medium grade nor with the lookup down.
t "p10-applied-high-not-resurrected"
setup
T0="$NOW"
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19 somelib 2.0
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
cve_add  somelib low "" ""
RUN_NOW="$T0"; runit; a_no_cards
mk_sim "$SIMFILE" somelib 2.0                           # openssh-server applied
cve_line somelib low "" ""
RUN_NOW="$((T0 + H))"; runit; a_no_cards
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.20 somelib 2.0   # its successor, a new version
cve_line openssh-server medium CVE-2026-3 https://ubuntu.com/security/CVE-2026-3
cve_add  somelib low "" ""
RUN_NOW="$((T0 + 3*H))"; runit; a_no_cards
a_first_has openssh-server "$((T0 + 3*H))"              # a fresh clock, not T0
: > "$CARDS"
RUN_NOW="$((T0 + 3*H + GRACE))"; runit
a_card_sev security-updates warning
grep -q 'E=security-updates|S=triggered|V=critical' "$CARDS" && bad "the applied High was resurrected for its successor" || ok
a_detail_lacks security-updates 'CVE-2026-1'
: > "$CARDS"; cve_line somelib low "" ""                # openssh-server ungraded this run
RUN_NOW="$((T0 + 4*H + GRACE))"; runit
grep -q 'E=security-updates|S=triggered|V=critical' "$CARDS" && bad "a stale grade paged through a lookup blip" || ok
a_card monitor-unreadable

# 37. a run whose clock read failed (NOW=0, the `date +%s` fallback) is UNREADABLE and
#     touches neither state file; the next good run still pages from the kept clock.
t "p11-zero-clock-unreadable"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
: > "$FIRST"
seed_row openssh-server "$((NOW - 100000))" 1:9.6p1-13.19 0 high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
b1=$(cksum < "$STATE/pending-since.security-updates"); b2=$(cksum < "$FIRST")
RUN_NOW=0; runit
a_card monitor-unreadable; a_no_card security-updates
[ "$(cksum < "$STATE/pending-since.security-updates")" = "$b1" ] && ok || bad "episode line changed on a NOW=0 run"
[ "$(cksum < "$FIRST")" = "$b2" ] && ok || bad "first-seen table changed on a NOW=0 run"
: > "$CARDS"
RUN_NOW="$NOW"; runit
a_card_sev security-updates critical
a_detail_has security-updates 'openssh-server (pending 27h)'

# 38. a table that disagrees with the episode line is not trusted. After a rollback to the
#     old single-clock code (which never removes the table) and a re-upgrade, the stale
#     table must not make a package the old code had tracked since T-100000 look new:
#     the episode start is used (migration), so the stuck page is not pushed back.
t "p12-stale-table-after-rollback-migrates"
setup
mk_sim "$SIMFILE" openssh-server 1:9.6p1-13.19
cve_line openssh-server high CVE-2026-1 https://ubuntu.com/security/CVE-2026-1
seed_clock "$((NOW - 100000)) 1 high openssh-server CVE-2026-1 https://ubuntu.com/security/CVE-2026-1"
: > "$FIRST"
seed_row oldpkg "$((NOW - 200000))" 1.0 0 - - -         # left over from before the rollback
runit; a_card_sev security-updates critical
a_first_has openssh-server "$((NOW - 100000))"
a_first_lacks oldpkg

# 39. check 6: a world-writable directory on the path to the root-run scripts
#     raises ONE quiet card, stays quiet while it stands, and resolves once fixed.
t "script-path-writable-raises-once-and-resolves"
setup
chmod 0777 "$SP_ROOT"
runit; a_exit0; a_card_sev script-path-writable warning; a_detail_has script-path-writable "$SP_ROOT"
a_detail_lacks script-path-writable "$SP_DIR "
: > "$CARDS"; runit; a_no_card script-path-writable
chmod 0755 "$SP_ROOT"; : > "$CARDS"; runit; a_card_state script-path-writable resolved

# 40. a sticky world-writable directory (like /tmp) is not flagged, a world-writable
#     script or transport is, and a clean path posts nothing.
t "script-path-sticky-ok-file-flagged"
setup
runit; a_no_card script-path-writable
chmod 1777 "$SP_ROOT"; runit; a_no_card script-path-writable
chmod 0755 "$SP_ROOT"; chmod 0666 "$SP_DIR/nethersec-report.sh"
runit; a_card_sev script-path-writable warning; a_detail_has script-path-writable "$SP_DIR/nethersec-report.sh"

# 41. Raspberry Pi OS: Chromium, the kernel and libc6 come from the Raspberry Pi archive, whose
#     suite is `stable`, not `-security`. By default such a line is NOT a security update...
t "extra-origin-off-by-default"
setup
SIMFILE="$WORK/sim_rpi"
{ echo "Reading package lists..."
  echo "Inst chromium [1:155.0-1+rpt1] (1:156.0-1+rpt1 Raspberry Pi Foundation:stable [arm64])"
  echo "Inst libc6 [2.41-12+rpt1+deb13u4] (2.41-12+rpt1+deb13u5 Raspberry Pi Foundation:stable [arm64])"
  echo "Inst nano [8.4-1] (8.4-2 Debian:13.7/stable [arm64])"
  echo "2 upgraded, 0 newly installed, 0 to remove."; } > "$SIMFILE"
CVE_LOOKUP=0
seed_clock "$((NOW - 100000)) 2  "
runit; a_exit0; a_no_card security-updates; a_clock_gone

# 42. ...but with HOSTSEC_SECURITY_ORIGIN_RE naming the archive, a stuck one cards quietly
#     (Raspberry Pi OS runs with the Ubuntu CVE grading off), and a plain Debian update still does not.
t "extra-origin-stuck-quiet-card"
setup
SIMFILE="$WORK/sim_rpi"
CVE_LOOKUP=0; XRE='Raspberry.Pi.Foundation:'
seed_clock "$((NOW - 100000)) 2  "
runit; a_exit0; a_card_sev security-updates warning
a_detail_has security-updates 'chromium'; a_detail_has security-updates 'libc6'
a_detail_lacks security-updates 'nano'

# 43. ...and while within grace it stays silent (the nightly auto-upgrade applies it first).
t "extra-origin-within-grace-silent"
setup
SIMFILE="$WORK/sim_rpi"
CVE_LOOKUP=0; XRE='Raspberry.Pi.Foundation:'
runit; a_exit0; a_no_cards; a_first_has chromium "$NOW"

# --- check 2: reboot pending (a card only for a High/Critical fix that is not live) ---
# Each case stages packages in the reboot flag, gives their installed versions, the
# list-mode lookup rows (name result top link ids), and the Livepatch / needrestart
# fixtures. A card is `reboot-security`; the weekly data is `reboot-pending` (info).
KIMG=linux-image-6.8.0-62-generic; KMOD=linux-modules-6.8.0-62-generic
mk_reboot() { # [name ver]...
  REBOOT="$WORK/reboot-required"; : > "$REBOOT"; : > "$REBOOT.pkgs"; : > "$DPKGFILE"
  while [ $# -ge 2 ]; do
    printf '%s\n' "$1" >> "$REBOOT.pkgs"; printf '%s\t%s\n' "$1" "$2" >> "$DPKGFILE"; shift 2
  done
  CVECMD="$BIN/cve-list"
}
row() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$CVEROWS"; }   # name result top link ids
lp_json() { # state fixes [running] [supported]
  printf '{"Client-Version":"10.1.0","Status":[{"Kernel":"6.8.0-59.59-generic","Running":%s,"Livepatch":{"CheckState":"checked","State":"%s","Version":"99.1","Fixes":"%s"},"Supported":"%s"}],"tier":"stable"}\n' \
    "${3:-true}" "$1" "$2" "${4:-supported}" > "$LPFILE"
  LPCMD="$BIN/mock-livepatch"
}
nr_out() { # [service]...
  printf 'NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-59-generic\nNEEDRESTART-KEXP: 6.8.0-62-generic\nNEEDRESTART-KSTA: 3\n' > "$NRFILE"
  for s in "$@"; do printf 'NEEDRESTART-SVC: %s\n' "$s" >> "$NRFILE"; done
  NRCMD="$BIN/mock-needrestart"
}
a_report_has()   { d=$(grep "E=reboot-pending|S=triggered|" "$CARDS" 2>/dev/null | tail -1 | sed 's/.*|D=//'); printf '%s' "$d" | grep -qF -- "$1" && ok || bad "expected the reboot-pending report to contain '$1' (got: $d)"; }
a_report_count() { n=$(grep -c "E=reboot-pending|S=triggered|" "$CARDS" 2>/dev/null); [ "${n:-0}" = "$1" ] && ok || bad "expected $1 reboot-pending report(s), got ${n:-0} ($(tr '\n' ' ' <"$CARDS"))"; }
a_report_sev()   { grep -q "E=reboot-pending|S=triggered|V=info|" "$CARDS" 2>/dev/null && ok || bad "expected the reboot-pending report at severity info (got: $(tr '\n' ' ' <"$CARDS"))"; }

# R1. no flag: no card, no report, no lookup, no Livepatch/needrestart needed
t "reboot-no-flag"
setup
CVECMD="$BIN/cve-list"
runit; a_exit0; a_no_cards
[ -f "$WORK/cvelist-invoked" ] && bad "the lookup ran with no reboot flag" || ok

# R2. low/medium only: no card; the reboot-pending report says checked, 0 High/Critical either way
t "reboot-lowmed-no-card"
setup
mk_reboot libc6 2.39-0ubuntu8.9 dbus 1.14.10-4ubuntu4.2
row libc6 medium CVE-2026-2 https://ubuntu.com/security/CVE-2026-2 ""
row dbus unknown "" "" ""
runit; a_exit0; a_no_card reboot-security; a_report_sev
a_report_has 'checked=yes'; a_report_has 'hc_covered=0 hc_uncovered=0'
a_report_has 'pkgs=dbus,libc6'; a_report_has 'livepatch=off'
[ -f "$WORK/cvelist-mode" ] && ok || bad "the reboot lookup must run in list mode (HOSTSEC_CVE_LIST=1)"
grep -qx 'libc6=2.39-0ubuntu8.9' "$WORK/cvelist-seen" 2>/dev/null && ok || bad "the INSTALLED version must reach the lookup (got: $(cat "$WORK/cvelist-seen" 2>/dev/null))"

# R3. kernel High, no Livepatch: card (quiet warning) naming the CVE, the package and
#     Livepatch off; the report counts it as not live
t "reboot-kernel-high-no-livepatch-card"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
runit; a_exit0; a_card_sev reboot-security warning; a_card_state reboot-security triggered
a_detail_has reboot-security 'CVE-2026-5001'; a_detail_has reboot-security "$KIMG"
a_detail_has reboot-security 'Livepatch: off'; a_detail_has reboot-security 'until testbox reboots'
a_detail_lacks reboot-security "$EMDASH"
a_report_has 'hc_covered=0 hc_uncovered=1'
grep -q 'V=critical' "$CARDS" && bad "a reboot card must never page" || ok

# R4. kernel High that Livepatch lists among its fixes (lowercase id) for the running
#     kernel: live, no card; the report counts it as covered, Livepatch on
t "reboot-kernel-high-in-livepatch-no-card"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
lp_json applied '* cve-2026-4000 * cve-2026-5001'
runit; a_exit0; a_no_card reboot-security
a_report_has 'hc_covered=1 hc_uncovered=0'; a_report_has 'livepatch=on'

# R5. Livepatch applied but its fixes do not list this CVE: card
t "reboot-kernel-high-not-in-fixes-card"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" critical CVE-2026-5002 https://ubuntu.com/security/CVE-2026-5002 CVE-2026-5002
lp_json applied '* cve-2026-4000'
runit; a_card_sev reboot-security warning; a_detail_has reboot-security 'Livepatch: applied'

# R6. the fix IS listed, but not for the running kernel, or for a kernel Livepatch does
#     not support, or the output is not JSON: not live, card
t "reboot-livepatch-not-running-or-unsupported-card"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
lp_json applied '* cve-2026-5001' false
runit; a_card reboot-security; a_report_has 'livepatch=off'
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
lp_json applied '* cve-2026-5001' true unsupported
runit; a_card reboot-security
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
printf 'Machine is not enabled\n' > "$LPFILE"; LPCMD="$BIN/mock-livepatch"
runit; a_exit0; a_card reboot-security; a_report_has 'livepatch=off'

# R7. Livepatch's other shape: lower-case keys and a list of fix objects (one unpatched)
t "reboot-livepatch-list-shape"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001,CVE-2026-5003
printf '{"status":[{"kernel":"6.8.0-59.59-generic","running":true,"livepatch":{"state":"applied","fixes":[{"name":"cve-2026-5001","patched":true},{"name":"CVE-2026-5003","patched":false}]}}]}\n' > "$LPFILE"
LPCMD="$BIN/mock-livepatch"
runit; a_card reboot-security
a_detail_has reboot-security 'CVE-2026-5003'; a_detail_lacks reboot-security 'CVE-2026-5001'
a_report_has 'hc_covered=1 hc_uncovered=1'

# R8. libc High with needrestart clean: live, no card
t "reboot-libc-high-needrestart-clean-no-card"
setup
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 high CVE-2026-6001 https://ubuntu.com/security/CVE-2026-6001 CVE-2026-6001
nr_out
runit; a_exit0; a_no_card reboot-security; a_report_has 'hc_covered=1 hc_uncovered=0'

# R9. libc High with a service still on the old code: card naming the service
t "reboot-libc-high-service-on-old-code-card"
setup
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 high CVE-2026-6001 https://ubuntu.com/security/CVE-2026-6001 CVE-2026-6001
nr_out dbus.service docker.service
runit; a_card_sev reboot-security warning
a_detail_has reboot-security 'CVE-2026-6001'; a_detail_has reboot-security 'dbus.service'
a_report_has 'hc_covered=0 hc_uncovered=1'

# R10. libc High and needrestart missing (or printing nothing it knows): not live, card
t "reboot-libc-high-no-needrestart-card"
setup
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 high CVE-2026-6001 https://ubuntu.com/security/CVE-2026-6001 CVE-2026-6001
runit; a_card reboot-security; a_detail_has reboot-security 'needrestart could not be read'
setup
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 high CVE-2026-6001 https://ubuntu.com/security/CVE-2026-6001 CVE-2026-6001
printf 'garbage\n' > "$NRFILE"; NRCMD="$BIN/mock-needrestart"
runit; a_card reboot-security

# R11. lookup error (an `error` row, or no row at all): no card, no monitor-unreadable,
#      and the report says not checked with no counts
t "reboot-lookup-error-not-checked"
setup
mk_reboot "$KIMG" 6.8.0-62.62 libc6 2.39-0ubuntu8.9
row "$KIMG" error "" "" ""
row libc6 high CVE-2026-6001 https://ubuntu.com/security/CVE-2026-6001 CVE-2026-6001
runit; a_exit0; a_no_card reboot-security; a_no_card monitor-unreadable
a_report_has 'checked=no'
d=$(grep "E=reboot-pending|" "$CARDS" | sed 's/.*|D=//'); printf '%s' "$d" | grep -q 'hc_' && bad "a not-checked report must carry no counts (got: $d)" || ok
setup
mk_reboot "$KIMG" 6.8.0-62.62
runit; a_no_card reboot-security; a_report_has 'checked=no'
# a four-column answer (list mode not honored) is not a check either
setup
mk_reboot "$KIMG" 6.8.0-62.62
printf '%s\thigh\tCVE-2026-5001\thttps://ubuntu.com/security/CVE-2026-5001\n' "$KIMG" > "$CVEROWS"
runit; a_no_card reboot-security; a_report_has 'checked=no'
# the CVE gate off: never checked
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
CVE_LOOKUP=0
runit; a_no_card reboot-security; a_report_has 'checked=no'

# R12. an open card is neither resolved nor re-raised by a run that could not check;
#      it resolves once the box has rebooted (the flag is gone)
t "reboot-card-kept-on-error-resolved-on-reboot"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
runit; a_card_state reboot-security triggered
: > "$CARDS"; : > "$CVEROWS"; row "$KIMG" error "" "" ""
RUN_NOW="$((NOW + 7*H))"; runit; a_no_card reboot-security
[ -f "$STATE/ev.reboot-security" ] && ok || bad "an error run must keep the open card's state"
: > "$CARDS"; rm -f "$REBOOT" "$REBOOT.pkgs"
RUN_NOW="$((NOW + 8*H))"; runit; a_card_state reboot-security resolved
[ -f "$STATE/reboot-pending.since" ] && bad "the since stamp must go with the flag" || ok

# R13. mixed: a kernel CVE Livepatch covers, the same id under two kernel packages
#      (counted once), and a libc CVE behind a service on old code: card for libc only
t "reboot-mixed-counts-once"
setup
mk_reboot "$KIMG" 6.8.0-62.62 "$KMOD" 6.8.0-62.62 libc6 2.39-0ubuntu8.9
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
row "$KMOD" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
row libc6 critical CVE-2026-6002 https://ubuntu.com/security/CVE-2026-6002 CVE-2026-6002
lp_json applied '* cve-2026-5001'
nr_out systemd-logind.service
runit; a_card reboot-security
a_detail_has reboot-security '1 High/Critical CVE(s)'; a_detail_has reboot-security 'CVE-2026-6002'
a_detail_lacks reboot-security 'CVE-2026-5001'; a_detail_has reboot-security 'Packages: libc6.'
a_report_has 'hc_covered=1 hc_uncovered=1'

# R14. a staged package no longer installed is skipped; junk lines in the list are
#      dropped and never echoed
t "reboot-uninstalled-skipped-junk-dropped"
setup
mk_reboot libc6 2.39-0ubuntu8.9
printf 'linux-image-6.8.0-60-generic\nBAD;rm -rf\n' >> "$REBOOT.pkgs"
row libc6 low "" "" ""
runit; a_no_card reboot-security; a_report_has 'checked=yes'
grep -q 'linux-image-6.8.0-60-generic=' "$WORK/cvelist-seen" && bad "an uninstalled package must not be graded" || ok
grep -q 'rm -rf' "$CARDS" && bad "a junk package line reached a report" || ok
a_report_has 'pkgs=libc6,linux-image-6.8.0-60-generic'

# R15. the reboot-pending report: unchanged data is not resent within 20h, is resent after it, a
#      change is sent at once, and a cleared flag sends one resolved report
t "reboot-weekly-report-throttle"
setup
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 medium "" "" ""
runit; a_report_count 1
RUN_NOW="$((NOW + 19*H))"; runit; a_report_count 1
RUN_NOW="$((NOW + 21*H))"; runit; a_report_count 2
printf 'dbus\n' >> "$REBOOT.pkgs"; printf 'dbus\t1.14\n' >> "$DPKGFILE"; row dbus low "" "" ""
RUN_NOW="$((NOW + 22*H))"; runit; a_report_count 3; a_report_has 'pkgs=dbus,libc6'
rm -f "$REBOOT" "$REBOOT.pkgs"
RUN_NOW="$((NOW + 23*H))"; runit; a_card_state reboot-pending resolved
: > "$CARDS"; RUN_NOW="$((NOW + 24*H))"; runit; a_no_card reboot-pending

# R16. an undelivered report is retried on the next run (not held for 20h)
t "reboot-weekly-report-retried"
setup
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 medium "" "" ""
: > "$WORK/report-fail"
runit; a_no_card reboot-pending
[ -f "$STATE/reboot-pending.sent" ] && bad "an undelivered report must not be marked sent" || ok
rm -f "$WORK/report-fail"
RUN_NOW="$((NOW + 1800))"; runit; a_report_count 1

# R16b. a report the hub refuses for this key (HTTP 403, a dm= key) is not sent again
#       every run: one log line, then the same data waits for the 20h resend interval;
#       changed data goes at once. The resolved report waits the same way.
ev_attempts() { n=$(grep -c "^$1|" "$WORK/attempts" 2>/dev/null); echo "${n:-0}"; }
a_ev_attempts() { n=$(ev_attempts "$1"); [ "$n" = "$2" ] && ok || bad "expected $2 $1 attempt(s), got $n ($(tr '\n' ' ' < "$WORK/attempts" 2>/dev/null))"; }
t "reboot-weekly-report-refused-waits"
setup
mk_reboot libc6 9.9-1
row libc6 medium "" "" ""
: > "$WORK/report-refused"
runit; a_exit0; a_no_card reboot-pending; a_ev_attempts reboot-pending 1
grep -qF "the hub refused the reboot-pending report for this key (HTTP 403" "$WORK/stderr" && ok \
  || bad "expected one log line for the refusal (got: $(tr '\n' ' ' < "$WORK/stderr"))"
[ "$(grep -c "the hub refused" "$WORK/stderr")" = 1 ] && ok || bad "exactly one refusal line"
[ -f "$STATE/reboot-pending.sent" ] && bad "a refused report must not be marked sent" || ok
RUN_NOW="$((NOW + 1800))"; runit; a_ev_attempts reboot-pending 1
grep -q "the hub refused" "$WORK/stderr" && bad "a refusal is logged once, not every run" || ok
RUN_NOW="$((NOW + 19*H))"; runit; a_ev_attempts reboot-pending 1
RUN_NOW="$((NOW + 21*H))"; runit; a_ev_attempts reboot-pending 2
printf 'dbus\n' >> "$REBOOT.pkgs"; printf 'dbus\t9.9-2\n' >> "$DPKGFILE"; row dbus low "" "" ""
RUN_NOW="$((NOW + 22*H))"; runit; a_ev_attempts reboot-pending 3
# the key may send it again (a new key): the next change is delivered and recorded
rm -f "$WORK/report-refused"
printf 'zlib1g\n' >> "$REBOOT.pkgs"; printf 'zlib1g\t9.9-3\n' >> "$DPKGFILE"; row zlib1g low "" "" ""
RUN_NOW="$((NOW + 23*H))"; runit; a_report_count 1; a_report_has 'pkgs=dbus,libc6,zlib1g'
[ -f "$STATE/reboot-pending.refused" ] && bad "a delivered report must drop the refusal" || ok
# the reboot happened, and the resolved report is refused: tried once, then it waits
rm -f "$REBOOT" "$REBOOT.pkgs"; : > "$WORK/report-refused"; : > "$WORK/attempts"; : > "$CARDS"
RUN_NOW="$((NOW + 24*H))"; runit; a_ev_attempts reboot-pending 1; a_no_card reboot-pending
RUN_NOW="$((NOW + 25*H))"; runit; a_ev_attempts reboot-pending 1
[ -f "$STATE/reboot-pending.sent" ] && ok || bad "the hub still holds the old data, so the resolved one stays owed"
rm -f "$WORK/report-refused"
RUN_NOW="$((NOW + 45*H))"; runit; a_card_state reboot-pending resolved
[ -f "$STATE/reboot-pending.sent" ] || [ -f "$STATE/reboot-pending.refused" ] && bad "a delivered resolve clears both records" || ok

# R16c. refused and never delivered, then the reboot: nothing to resolve, nothing kept
t "reboot-weekly-report-refused-then-cleared"
setup
mk_reboot libc6 9.9-1
row libc6 medium "" "" ""
: > "$WORK/report-refused"
runit; a_ev_attempts reboot-pending 1
rm -f "$REBOOT" "$REBOOT.pkgs"
RUN_NOW="$((NOW + 1800))"; runit; a_ev_attempts reboot-pending 1
[ -f "$STATE/reboot-pending.refused" ] && bad "the refusal record must go with the flag" || ok

# R17. the first report waits for the arming delay after this version first runs
t "reboot-weekly-report-arming"
setup
ARM=7200
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 medium "" "" ""
runit; a_no_card reboot-pending
RUN_NOW="$((NOW + 3600))"; runit; a_no_card reboot-pending
RUN_NOW="$((NOW + 7200))"; runit; a_report_count 1

# R18. since: the first sight seeds it from the flag's mtime and later runs keep it;
#      a future or garbled stamp is seeded again
t "reboot-since-seeded-and-kept"
setup
mk_reboot libc6 2.39-0ubuntu8.9
row libc6 medium "" "" ""
touch -d "@$((NOW - 41*DAY))" "$REBOOT" 2>/dev/null
runit; a_report_has "since=$((NOW - 41*DAY))"
touch -d "@$((NOW - 2*DAY))" "$REBOOT" 2>/dev/null       # a later staged install
RUN_NOW="$((NOW + 21*H))"; runit; a_report_has "since=$((NOW - 41*DAY))"
printf 'garbage\n' > "$STATE/reboot-pending.since"
RUN_NOW="$((NOW + 42*H))"; runit; a_report_has "since=$((NOW - 2*DAY))"

# --- a kernel left behind with no reboot flag (Livepatch suppresses the flag) ---------
# The box runs 6.8.0-62-generic and has 6.8.0-67-generic installed. An HWE image (other
# base) and a lowlatency image (other flavor) are newer still and must be ignored.
KNEW=linux-image-6.8.0-67-generic
mk_kernel() { # [running release]
  KREL="${1:-6.8.0-62-generic}"; CVECMD="$BIN/cve-list"
  printf '%s\t%s\n' \
    linux-image-6.8.0-62-generic 6.8.0-62.62 \
    "$KNEW" 6.8.0-67.67 \
    linux-image-7.0.0-14-generic 7.0.0-14.14~24.04.1 \
    linux-image-6.8.0-70-lowlatency 6.8.0-70.70 >> "$DPKGFILE"
}
a_seen_lacks() { grep -q -- "$1" "$WORK/cvelist-seen" 2>/dev/null && bad "'$1' must not reach the lookup (got: $(cat "$WORK/cvelist-seen"))" || ok; }

# R20. behind, no flag, only medium: no card; the newer kernel is graded over the range
#      from the running version, and the report names it. After the reboot (the running
#      kernel is the newest) the report resolves and the since stamp goes.
t "reboot-kernel-behind-no-flag-medium"
setup
mk_kernel
row "$KNEW" medium CVE-2026-2 https://ubuntu.com/security/CVE-2026-2 ""
runit; a_exit0; a_no_card reboot-security
a_report_has "pkgs=$KNEW more=0"; a_report_has 'checked=yes'; a_report_has 'hc_covered=0 hc_uncovered=0'
grep -qx "$KNEW=6.8.0-67.67|6.8.0-62.62" "$WORK/cvelist-seen" 2>/dev/null && ok \
  || bad "the newer kernel must reach the lookup with the running version (got: $(cat "$WORK/cvelist-seen" 2>/dev/null))"
a_seen_lacks 'linux-image-7.0.0'; a_seen_lacks 'lowlatency'
KREL=6.8.0-67-generic
RUN_NOW="$((NOW + H))"; runit; a_card_state reboot-pending resolved; a_no_card reboot-security
[ -f "$STATE/reboot-pending.since" ] && bad "the since stamp must go once the newest kernel runs" || ok

# R21. behind, no flag, a High fix and Livepatch with nothing applied: a quiet card
#      naming the CVE and the newer kernel
t "reboot-kernel-behind-no-flag-high-card"
setup
mk_kernel
row "$KNEW" high CVE-2026-80883 https://ubuntu.com/security/CVE-2026-80883 CVE-2026-80883
lp_json nothing-to-apply ''
runit; a_exit0; a_card_sev reboot-security warning; a_card_state reboot-security triggered
a_detail_has reboot-security 'CVE-2026-80883'; a_detail_has reboot-security "Packages: $KNEW."
a_detail_has reboot-security 'Livepatch: nothing-to-apply'
a_report_has 'livepatch=on'; a_report_has 'hc_covered=0 hc_uncovered=1'
grep -q 'V=critical' "$CARDS" && bad "a reboot card must never page" || ok

# R22. the running kernel is the newest of its base and flavor: nothing pending, no
#      lookup; a running kernel no package owns is not judged either
t "reboot-kernel-current-no-flag"
setup
mk_kernel 6.8.0-67-generic
runit; a_exit0; a_no_cards
[ -f "$WORK/cvelist-invoked" ] && bad "the lookup ran with nothing pending" || ok
setup
mk_kernel 6.8.0-61-generic
runit; a_exit0; a_no_cards
[ -f "$WORK/cvelist-invoked" ] && bad "an unowned running kernel must not be judged" || ok

# R23. behind but not graded (no answer from the lookup): not checked and no card at
#      first; once the newer kernel has waited 3 days since its install it is a card
#      anyway; a later run that grades it decides as usual and resolves the card
t "reboot-kernel-behind-ungraded-safety-net"
setup
mk_kernel
touch -d "@$((NOW - DAY))" "$DPKGINFO/$KNEW.list"
runit; a_exit0; a_no_card reboot-security
a_report_has 'checked=no'; a_report_has "since=$((NOW - DAY))"
RUN_NOW="$((NOW + 2*DAY))"; runit; a_card_sev reboot-security warning
a_detail_has reboot-security 'could not be checked yet'; a_detail_has reboot-security "$KNEW (6.8.0-67.67)"
a_detail_has reboot-security 'installed 3 day(s) ago'; a_detail_has reboot-security 'kernel 6.8.0-62-generic (6.8.0-62.62)'
grep -q 'V=critical' "$CARDS" && bad "the safety-net card must never page" || ok
row "$KNEW" medium "" "" ""
: > "$CARDS"; RUN_NOW="$((NOW + 2*DAY + H))"; runit; a_card_state reboot-security resolved
a_report_has 'checked=yes'

# R24. the first sight seeds since from the newer kernel's install time
t "reboot-kernel-behind-since-seeded-from-dpkg"
setup
mk_kernel
touch -d "@$((NOW - 4*DAY))" "$DPKGINFO/$KNEW.list"
runit; a_card reboot-security; a_detail_has reboot-security 'could not be checked yet'
a_report_has "since=$((NOW - 4*DAY))"; a_report_has 'checked=no'

# R25. a flag that names only apparmor, with a kernel left behind: both are staged
t "reboot-flag-apparmor-plus-kernel-behind"
setup
mk_reboot apparmor 4.0.1really4.0.1-0ubuntu0.24.04.5
mk_kernel
row apparmor low "" "" ""
row "$KNEW" medium "" "" ""
runit; a_exit0; a_no_card reboot-security
a_report_has "pkgs=apparmor,$KNEW more=0"; a_report_has 'checked=yes'

# R26. with a flag, the safety net still times the kernel from its own install, not from
#      the flag (here the flag is new and the kernel has waited 4 days)
t "reboot-flag-plus-kernel-ungraded-uses-kernel-install-time"
setup
mk_reboot apparmor 4.0.1really4.0.1-0ubuntu0.24.04.5
mk_kernel
touch -d "@$NOW" "$REBOOT"; touch -d "@$((NOW - 4*DAY))" "$DPKGINFO/$KNEW.list"
row apparmor low "" "" ""
runit; a_exit0; a_card_sev reboot-security warning
a_detail_has reboot-security 'could not be checked yet'; a_detail_has reboot-security 'installed 4 day(s) ago'
a_report_has "since=$NOW"; a_report_has 'checked=no'

# R27. the unit's NoNewPrivileges blocks the snap (the direct call returns nothing):
#      Livepatch is read through one transient systemd-run unit, so a fix it lists is
#      live; the unit keeps a read-only home and its own /tmp
t "reboot-livepatch-read-through-systemd-run"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
lp_json applied '* cve-2026-5001'
LPSANDBOX=1; SRUNCMD="$BIN/mock-systemd-run"
runit; a_exit0; a_no_card reboot-security
a_report_has 'livepatch=on'; a_report_has 'hc_covered=1 hc_uncovered=0'
s=$(cat "$WORK/srun-args" 2>/dev/null)
for w in '--wait' '--pipe' '--collect' '--no-ask-password' 'RuntimeMaxSec=20' 'ProtectHome=read-only' 'PrivateTmp=yes' "$BIN/mock-livepatch status --format json"; do
  case "$s" in *"$w"*) ok ;; *) bad "systemd-run must get '$w' (got: $s)" ;; esac
done

# R28. a direct call that answers never goes through systemd-run
t "reboot-livepatch-direct-skips-systemd-run"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
lp_json applied '* cve-2026-5001'
SRUNCMD="$BIN/mock-systemd-run"
runit; a_no_card reboot-security; a_report_has 'livepatch=on'
[ -f "$WORK/srun-args" ] && bad "systemd-run ran although the direct call answered" || ok

# R29. blocked and systemd-run fails too (or is missing): Livepatch reads as off, so
#      the fix is not live and the card says so
t "reboot-livepatch-blocked-reads-off"
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
lp_json applied '* cve-2026-5001'
LPSANDBOX=1; SRUNCMD="$BIN/mock-systemd-run"; : > "$WORK/srun-fail"
runit; a_exit0; a_card reboot-security; a_detail_has reboot-security 'Livepatch: off'
a_report_has 'livepatch=off'
setup
mk_reboot "$KIMG" 6.8.0-62.62
row "$KIMG" high CVE-2026-5001 https://ubuntu.com/security/CVE-2026-5001 CVE-2026-5001
lp_json applied '* cve-2026-5001'
LPSANDBOX=1
runit; a_exit0; a_card reboot-security; a_report_has 'livepatch=off'

# ===========================================================================
# Check 7: vendor apt packages nothing installs.
# intro_row: name candidate origin -> one apt-introspect.py row (9 columns)
TPF="$STATE/first-seen.thirdparty.tsv"
intro_row() { printf '%s\t%s\tamd64\t%s\tpkgs.example.com\tstable\t1\t0\t%s\n' "$1" "$2" "$3" "$1" >> "$INTROFILE"; }
WEEK=604800

# T1. a vendor package inside the grace is silent; its clock starts at first sight
t "thirdparty-within-grace-silent"
setup
intro_row vendor-agent 2.4.0 ExampleVendor
printf 'vendor-agent\t2.3.1\n' > "$DPKGFILE"
runit; a_exit0; a_no_cards
awk -F'\t' -v n="$NOW" '$1 == "vendor-agent" && $2 == n && $3 == "2.4.0" { f = 1 } END { exit !f }' "$TPF" 2>/dev/null \
  && ok || bad "expected vendor-agent first seen at $NOW (got: $(cat "$TPF" 2>/dev/null))"
RUN_NOW="$((NOW + WEEK - 1))"; runit; a_no_cards

# T2. past the grace: ONE quiet card naming installed -> candidate and the age
t "thirdparty-past-grace-cards"
setup
intro_row vendor-agent 2.4.0 ExampleVendor
intro_row docker-ce 5:27.2.0-1 Docker
printf 'vendor-agent\t2.3.1\ndocker-ce\t5:27.1.0-1\n' > "$DPKGFILE"
runit; a_no_cards
RUN_NOW="$((NOW + 8*DAY))"; runit
a_card_sev thirdparty-updates warning
a_detail_has thirdparty-updates 'vendor-agent 2.3.1 -> 2.4.0 (8d)'
a_detail_has thirdparty-updates 'docker-ce 5:27.1.0-1 -> 5:27.2.0-1 (8d)'
a_detail_has thirdparty-updates '2 package(s)'
a_detail_lacks thirdparty-updates "$EMDASH"
# still behind an hour later: no second post inside the resurface window
: > "$CARDS"; RUN_NOW="$((NOW + 8*DAY + H))"; runit; a_no_card thirdparty-updates

# T3. a newer vendor release does not restart the clock
t "thirdparty-new-release-keeps-clock"
setup
intro_row vendor-agent 2.4.0 ExampleVendor
runit
: > "$INTROFILE"; intro_row vendor-agent 2.4.1 ExampleVendor
RUN_NOW="$((NOW + 8*DAY))"; runit
a_card thirdparty-updates; a_detail_has thirdparty-updates 'vendor-agent ? -> 2.4.1 (8d)'

# T4. distro origins are check 1's, and the ignore list is skipped
t "thirdparty-distro-and-ignored-skipped"
setup
intro_row libc6 2.39-0ubuntu8.6 Ubuntu
intro_row esm-pkg 1.2 UbuntuESM
intro_row somepkg 3.1.0 vendor/somepkg/stable
TP_IGNORE="somepkg"
runit; RUN_NOW="$((NOW + 30*DAY))"; runit
a_no_cards
[ -f "$TPF" ] && bad "nothing pending must leave no table (got: $(cat "$TPF"))" || ok

# T5. a failed read publishes nothing for the check, folds into monitor-unreadable,
#     and keeps the clocks
t "thirdparty-unreadable"
setup
intro_row vendor-agent 2.4.0 ExampleVendor
runit
: > "$WORK/intro-fail"
RUN_NOW="$((NOW + 8*DAY))"; runit
a_no_card thirdparty-updates
a_card monitor-unreadable; a_detail_has monitor-unreadable 'thirdparty-updates'
grep -q "^vendor-agent$TAB$NOW$TAB" "$TPF" 2>/dev/null && ok || bad "the clock must survive a failed read (got: $(cat "$TPF" 2>/dev/null))"
rm -f "$WORK/intro-fail"
RUN_NOW="$((NOW + 8*DAY + H))"; runit
a_card_sev thirdparty-updates warning; a_card_state monitor-unreadable resolved

# T6. installed: the card resolves once and the table goes
t "thirdparty-installed-resolves"
setup
intro_row vendor-agent 2.4.0 ExampleVendor
runit; RUN_NOW="$((NOW + 8*DAY))"; runit; a_card thirdparty-updates
: > "$CARDS"; : > "$INTROFILE"
RUN_NOW="$((NOW + 8*DAY + H))"; runit
a_card_state thirdparty-updates resolved
[ -f "$TPF" ] && bad "expected the table removed once nothing is behind" || ok

# T7. switched off: no read, no card, no table
t "thirdparty-disabled"
setup
intro_row vendor-agent 2.4.0 ExampleVendor
TP_ENABLE=0
runit; RUN_NOW="$((NOW + 30*DAY))"; runit
a_no_cards
[ -f "$TPF" ] && bad "a disabled check must keep no table" || ok

# T8. more than eight late packages: the first eight are named, the rest counted
t "thirdparty-detail-capped"
setup
for i in 1 2 3 4 5 6 7 8 9 10; do intro_row "vpkg$i" "2.$i" Vendor; done
runit; RUN_NOW="$((NOW + 8*DAY))"; runit
a_detail_has thirdparty-updates '10 package(s)'
a_detail_has thirdparty-updates 'and 2 more'

# ===========================================================================
# Check 8: Docker live-restore.

# L1. live-restore on: no card
t "live-restore-on-silent"
setup; DOCKERCMD="$BIN/mock-docker"
runit; a_exit0; a_no_cards

# L2. off: ONE quiet card naming the fix; no second post inside the resurface window
t "live-restore-off-cards"
setup; DOCKERCMD="$BIN/mock-docker"; echo false > "$WORK/docker-lr"
runit; a_card_sev docker-live-restore warning; a_card_state docker-live-restore triggered
a_detail_has docker-live-restore "sudo bash $(CDPATH= cd -- "$HERE/.." && pwd -P)/docker-live-restore.sh"
a_detail_lacks docker-live-restore "$EMDASH"
: > "$CARDS"; RUN_NOW="$((NOW + H))"; runit; a_no_card docker-live-restore

# L3. turned back on: resolves once
t "live-restore-fixed-resolves"
setup; DOCKERCMD="$BIN/mock-docker"; echo false > "$WORK/docker-lr"
runit; a_card docker-live-restore
: > "$CARDS"; echo true > "$WORK/docker-lr"; RUN_NOW="$((NOW + H))"; runit
a_card_state docker-live-restore resolved

# L4. a daemon that does not answer is unreadable, never "off", and an open card stays
t "live-restore-unreadable"
setup; DOCKERCMD="$BIN/mock-docker"; echo false > "$WORK/docker-lr"
runit; a_card docker-live-restore
: > "$CARDS"; : > "$WORK/docker-fail"; RUN_NOW="$((NOW + H))"; runit
a_no_card docker-live-restore
a_card monitor-unreadable; a_detail_has monitor-unreadable 'docker-live-restore'
# an answer that is neither true nor false is unreadable too
setup; DOCKERCMD="$BIN/mock-docker"; echo '<no value>' > "$WORK/docker-lr"
runit; a_no_card docker-live-restore; a_card monitor-unreadable

# L5. no Docker installed (every other test runs this way): nothing
t "live-restore-no-docker"
setup; echo false > "$WORK/docker-lr"
runit; a_no_cards

# L6. switched off: no card even when it is off
t "live-restore-disabled"
setup; DOCKERCMD="$BIN/mock-docker"; echo false > "$WORK/docker-lr"; LR_ENABLE=0
runit; a_no_cards

# ===========================================================================
# Checks 9-12: box drift.
ubuntu() { printf 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n' > "$OSREL"; }
lp_ok() { lp_json applied '* cve-2026-5001'; LPCMD="$BIN/mock-livepatch"; }

# V1. Ubuntu, Livepatch applied and supported: no card, and no failed read
t "livepatch-ok-silent"
setup; ubuntu; lp_ok
runit; a_exit0; a_no_cards
lp_json nothing-to-apply ''; runit; a_no_cards

# V2. the client is missing: ONE quiet card; installing and enabling it resolves
t "livepatch-missing-cards-then-resolves"
setup; ubuntu
runit; a_card_sev livepatch-off warning; a_card_state livepatch-off triggered
a_detail_has livepatch-off 'not installed'; a_detail_lacks livepatch-off "$EMDASH"
# the fix it suggests takes no token on the command line (AGENTS.md rule 9)
a_detail_has livepatch-off 'sudo pro attach'; a_detail_has livepatch-off 'sudo pro enable livepatch'
a_detail_lacks livepatch-off 'token>'; a_detail_lacks livepatch-off 'canonical-livepatch enable'
: > "$CARDS"; RUN_NOW="$((NOW + H))"; runit; a_no_card livepatch-off
: > "$CARDS"; lp_ok; RUN_NOW="$((NOW + 2*H))"; runit
a_card_state livepatch-off resolved; a_no_card monitor-unreadable

# V3. installed but not enabled (plain text, no JSON)
t "livepatch-not-enabled"
setup; ubuntu; LPCMD="$BIN/mock-livepatch"
printf "Machine is not enabled. Please run 'sudo canonical-livepatch enable' with the token obtained from https://ubuntu.com/livepatch.\n" > "$LPFILE"
runit; a_card_sev livepatch-off warning; a_detail_has livepatch-off 'not enabled'
a_detail_has livepatch-off 'sudo pro enable livepatch'; a_detail_lacks livepatch-off 'token>'

# V4. the running kernel is not supported, or its patch failed: a card naming why
t "livepatch-unsupported-or-failed"
setup; ubuntu; LPCMD="$BIN/mock-livepatch"
lp_json applied '* cve-2026-5001' true unsupported
runit; a_card livepatch-off; a_detail_has livepatch-off 'does not support the running kernel 6.8.0-59.59-generic (unsupported)'
setup; ubuntu; LPCMD="$BIN/mock-livepatch"
lp_json apply-failed ''
runit; a_card livepatch-off; a_detail_has livepatch-off 'cannot patch the running kernel 6.8.0-59.59-generic (apply-failed)'
setup; ubuntu; LPCMD="$BIN/mock-livepatch"
lp_json kernel-upgrade-required ''
runit; a_card livepatch-off; a_detail_has livepatch-off '(kernel-upgrade-required)'

# V5. an answer it cannot read is unreadable: no card of its own, an open one stays
t "livepatch-unreadable"
setup; ubuntu
runit; a_card livepatch-off
: > "$CARDS"; LPCMD="$BIN/mock-livepatch"; printf 'error: cannot connect to the daemon\n' > "$LPFILE"
RUN_NOW="$((NOW + H))"; runit
a_no_card livepatch-off; a_card monitor-unreadable; a_detail_has monitor-unreadable 'livepatch'
[ -f "$STATE/ev.livepatch-off" ] && ok || bad "a failed read must keep the open card's state"
# no entry for the running kernel, or support it cannot tell, is a failed read too
setup; ubuntu; LPCMD="$BIN/mock-livepatch"; lp_json applied '' false
runit; a_no_card livepatch-off; a_card monitor-unreadable
setup; ubuntu; LPCMD="$BIN/mock-livepatch"; lp_json applied '' true unknown
runit; a_no_card livepatch-off; a_card monitor-unreadable

# V6. read through systemd-run when the unit sandbox blocks the snap, with a warning
#     line before the JSON
t "livepatch-through-systemd-run"
setup; ubuntu; lp_ok; LPSANDBOX=1; SRUNCMD="$BIN/mock-systemd-run"
runit; a_no_cards
setup; ubuntu; LPCMD="$BIN/mock-livepatch"
{ echo 'WARNING: snapd is out of date'; lp_json applied '' && cat "$LPFILE"; } > "$WORK/lp.mixed"; mv "$WORK/lp.mixed" "$LPFILE"
runit; a_no_cards

# V7. one Livepatch read a run, shared with the reboot check
t "livepatch-read-once-a-run"
setup; ubuntu; lp_ok; REBOOT="$WORK/reboot-v7"; : > "$REBOOT"
runit; a_no_card livepatch-off
[ "$(wc -l < "$WORK/lp-calls" 2>/dev/null | tr -d ' ')" = 1 ] && ok || bad "expected one Livepatch call (got: $(wc -l < "$WORK/lp-calls" 2>/dev/null))"
rm -f "$REBOOT"

# V8. not Ubuntu (Raspberry Pi OS): off by default; 1 forces it on, 0 turns it off on Ubuntu
t "livepatch-gate"
setup
runit; a_no_cards
setup; LP_CHECK=1
runit; a_card livepatch-off
setup; ubuntu; LP_CHECK=0
runit; a_no_cards

# I1. the IP-options drop is on: no card; it ran with --check
t "ipopt-on-silent"
setup; ubuntu; lp_ok
runit; a_exit0; a_no_cards
[ "$(cat "$WORK/ipopt-args" 2>/dev/null)" = "--check" ] && ok || bad "expected --check (got: $(cat "$WORK/ipopt-args" 2>/dev/null))"

# I2. off: ONE quiet card quoting what is off and the fix; turning it on resolves
t "ipopt-off-cards-then-resolves"
setup; ubuntu; lp_ok
printf 'ipv4-options-drop: table NOT loaded. Turn it on: sudo bash /x/ipv4-options-drop.sh\nipv4-options-drop: nethersec-ipv4-options-drop.service is NOT enabled, so a reboot would drop the table.\n' > "$WORK/ipopt.out"
echo 1 > "$WORK/ipopt.rc"
runit; a_card_sev ipv4-options-drop-off warning
a_detail_has ipv4-options-drop-off 'table NOT loaded.'
a_detail_has ipv4-options-drop-off 'is NOT enabled'
a_detail_has ipv4-options-drop-off "sudo bash $(CDPATH= cd -- "$HERE/.." && pwd -P)/ipv4-options-drop.sh"
a_detail_lacks ipv4-options-drop-off '/x/'; a_detail_lacks ipv4-options-drop-off "$EMDASH"
: > "$CARDS"; RUN_NOW="$((NOW + H))"; runit; a_no_card ipv4-options-drop-off
: > "$CARDS"; echo 0 > "$WORK/ipopt.rc"; : > "$WORK/ipopt.out"; RUN_NOW="$((NOW + 2*H))"; runit
a_card_state ipv4-options-drop-off resolved

# I3. no nft at all is off too
t "ipopt-no-nft"
setup; ubuntu; lp_ok
echo 'ipv4-options-drop: nft is not installed here (apt-get install nftables).' > "$WORK/ipopt.out"; echo 1 > "$WORK/ipopt.rc"
runit; a_card ipv4-options-drop-off; a_detail_has ipv4-options-drop-off 'nft is not installed'

# I4. a failure that is not "off" (no root, a bad arg, a timeout) is unreadable
t "ipopt-unreadable"
setup; ubuntu; lp_ok
echo 'ipv4-options-drop: cannot read the nftables ruleset (run as root).' > "$WORK/ipopt.out"; echo 1 > "$WORK/ipopt.rc"
runit; a_no_card ipv4-options-drop-off; a_card monitor-unreadable; a_detail_has monitor-unreadable 'ipv4-options-drop'
setup; ubuntu; lp_ok
echo 'ipv4-options-drop: table NOT loaded.' > "$WORK/ipopt.out"; echo 124 > "$WORK/ipopt.rc"
runit; a_no_card ipv4-options-drop-off; a_card monitor-unreadable

# I5. not Ubuntu: off by default
t "ipopt-gate"
setup; echo 1 > "$WORK/ipopt.rc"; echo 'ipv4-options-drop: table NOT loaded.' > "$WORK/ipopt.out"
runit; a_no_cards
[ -f "$WORK/ipopt-args" ] && bad "the check must not run off Ubuntu" || ok

sshd_cfg() { printf 'port 22\npasswordauthentication %s\nkbdinteractiveauthentication %s\nusepam %s\npubkeyauthentication yes\n' "$1" "$2" "$3" > "$WORK/sshd.out"; }

# S1. key-only sshd: no card; no sshd at all: nothing either
t "sshd-key-only-silent"
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg no no yes
runit; a_exit0; a_no_cards
setup; sshd_cfg yes no yes
runit; a_no_cards

# S2. password auth on: ONE quiet card naming it and the fix; fixing it resolves
t "sshd-passwords-cards-then-resolves"
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg yes no yes
runit; a_card_sev ssh-password-auth warning; a_card_state ssh-password-auth triggered
a_detail_has ssh-password-auth '(passwordauthentication yes)'
a_detail_has ssh-password-auth '/etc/ssh/sshd_config.d'
a_detail_lacks ssh-password-auth 'kbdinteractiveauthentication yes'; a_detail_lacks ssh-password-auth "$EMDASH"
: > "$CARDS"; RUN_NOW="$((NOW + H))"; runit; a_no_card ssh-password-auth
: > "$CARDS"; RUN_NOW="$((NOW + 7*H))"; runit
a_card_state ssh-password-auth triggered   # re-asserted after the 6h resurface window
: > "$CARDS"; sshd_cfg no no yes; RUN_NOW="$((NOW + 8*H))"; runit
a_card_state ssh-password-auth resolved

# S3. keyboard-interactive with PAM asks for the password too; without PAM it does not
t "sshd-kbdinteractive-pam"
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg no yes yes
runit; a_card ssh-password-auth; a_detail_has ssh-password-auth 'kbdinteractiveauthentication yes with usepam yes'
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg no yes no
runit; a_no_cards
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg yes yes yes
runit; a_detail_has ssh-password-auth 'passwordauthentication yes, and kbdinteractiveauthentication yes'

# S4. sshd -T fails, or prints no passwordauthentication line: unreadable, card kept
t "sshd-unreadable"
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg yes no yes
runit; a_card ssh-password-auth
: > "$CARDS"; : > "$WORK/sshd-fail"; RUN_NOW="$((NOW + H))"; runit
a_no_card ssh-password-auth; a_card monitor-unreadable; a_detail_has monitor-unreadable 'sshd'
[ -f "$STATE/ev.ssh-password-auth" ] && ok || bad "a failed read must keep the open card's state"
setup; SSHDCMD="$BIN/mock-sshd"; printf 'port 22\n' > "$WORK/sshd.out"
runit; a_no_card ssh-password-auth; a_card monitor-unreadable

# S4b. sshd -T cannot run (no /run/sshd before the first connection): -G is read instead
t "sshd-T-fails-G-reads"
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg yes no yes; : > "$WORK/sshd-T-fail"
runit; a_card ssh-password-auth; a_no_card monitor-unreadable
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg no no yes; : > "$WORK/sshd-T-fail"
runit; a_no_cards
rm -f "$WORK/sshd-T-fail"

# S5. switched off: no card
t "sshd-disabled"
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg yes no yes; SSHD_CHECK=0
runit; a_no_cards

# S6. a state file from before the optional key (two fields) still throttles
t "transition-two-field-state"
setup; SSHDCMD="$BIN/mock-sshd"; sshd_cfg yes no yes
printf 'warning %s\n' "$((NOW - H))" > "$STATE/ev.ssh-password-auth"
runit; a_no_card ssh-password-auth

# ss -Htulnp lines: proto state local peer process
ss_add() { printf '%s %s 0 4096 %s %s users:(("%s",pid=%s,fd=3))\n' "$1" "$2" "$3" "$4" "$5" "${6:-100}" >> "$WORK/ss.out"; }
ss_base() {
  ss_add tcp LISTEN 0.0.0.0:22 '0.0.0.0:*' sshd
  ss_add tcp LISTEN '[::]:22' '[::]:*' sshd
  ss_add tcp LISTEN 0.0.0.0:443 '0.0.0.0:*' nginx
  ss_add udp UNCONN '[::]:443' '[::]:*' nginx
  ss_add tcp LISTEN 192.0.2.7:41234 '0.0.0.0:*' vpnd
  ss_add tcp LISTEN 127.0.0.1:6379 '0.0.0.0:*' redis-server
  ss_add udp UNCONN 127.0.0.53%lo:53 '0.0.0.0:*' systemd-resolve
  ss_add tcp LISTEN '[::1]:5432' '[::]:*' postgres
}
ALLOW="tcp/0.0.0.0:22 tcp/[::]:22 tcp/*:443 udp/*:443 tcp/192.0.2.7:*"

# N1. no allowlist: the check is off, and ss is not even run
t "listen-no-allowlist-off"
setup; ss_base; ss_add tcp LISTEN 0.0.0.0:6379 '0.0.0.0:*' docker-proxy
runit; a_exit0; a_no_cards
[ -f "$WORK/ss-args" ] && bad "ss must not run without an allowlist" || ok

# N2. every non-loopback socket allowed (exact, any address, any port); loopback ignored
t "listen-all-allowed"
setup; ss_base; LISTEN_ALLOW="$ALLOW"
runit; a_no_cards
[ "$(cat "$WORK/ss-args" 2>/dev/null)" = "-Htulnp" ] && ok || bad "expected ss -Htulnp (got: $(cat "$WORK/ss-args" 2>/dev/null))"
# a comma between tokens works too
setup; ss_base; LISTEN_ALLOW="tcp/0.0.0.0:22,tcp/[::]:22, tcp/*:443 udp/*:443 tcp/192.0.2.7:*"
runit; a_no_cards

# N3. a new public socket: ONE quiet card naming it and its process; quiet again within
#     the resurface window
t "listen-unexpected-cards"
setup; ss_base; LISTEN_ALLOW="$ALLOW"; ss_add tcp LISTEN 0.0.0.0:6379 '0.0.0.0:*' docker-proxy
runit; a_card_sev unexpected-listener warning; a_card_state unexpected-listener triggered
a_detail_has unexpected-listener '1 socket(s)'
a_detail_has unexpected-listener 'tcp/0.0.0.0:6379 (docker-proxy)'
a_detail_lacks unexpected-listener 'sshd'; a_detail_lacks unexpected-listener '127.0.0.1:6379'
a_detail_lacks unexpected-listener '127.0.0.53'; a_detail_lacks unexpected-listener '::1'; a_detail_lacks unexpected-listener "$EMDASH"
: > "$CARDS"; RUN_NOW="$((NOW + H))"; runit; a_no_card unexpected-listener

# N4. another one while raised: re-asserted at once, naming both; then both gone resolves
t "listen-new-set-reasserts"
setup; ss_base; LISTEN_ALLOW="$ALLOW"; ss_add tcp LISTEN 0.0.0.0:6379 '0.0.0.0:*' docker-proxy
runit; a_card unexpected-listener
: > "$CARDS"; ss_add udp UNCONN '[::]:5353' '[::]:*' avahi-daemon; RUN_NOW="$((NOW + H))"; runit
a_card_state unexpected-listener triggered; a_detail_has unexpected-listener '2 socket(s)'
a_detail_has unexpected-listener 'udp/[::]:5353 (avahi-daemon)'
# the same set with another pid is not a new set
sed 's/pid=100/pid=200/' "$WORK/ss.out" > "$WORK/ss.tmp" && mv "$WORK/ss.tmp" "$WORK/ss.out"
: > "$CARDS"; RUN_NOW="$((NOW + 2*H))"; runit
a_no_card unexpected-listener
: > "$CARDS"; : > "$WORK/ss.out"; ss_base; RUN_NOW="$((NOW + 3*H))"; runit
a_card_state unexpected-listener resolved

# N5. the same port on another address is not allowed by an exact token
t "listen-address-matters"
setup; ss_base; LISTEN_ALLOW="$ALLOW"; ss_add tcp LISTEN 0.0.0.0:41234 '0.0.0.0:*' vpnd
runit; a_card unexpected-listener; a_detail_has unexpected-listener 'tcp/0.0.0.0:41234 (vpnd)'
a_detail_lacks unexpected-listener '192.0.2.7'

# N6. ss fails: unreadable, the open card stays
t "listen-unreadable"
setup; ss_base; LISTEN_ALLOW="$ALLOW"; ss_add tcp LISTEN 0.0.0.0:6379 '0.0.0.0:*' docker-proxy
runit; a_card unexpected-listener
: > "$CARDS"; : > "$WORK/ss-fail"; RUN_NOW="$((NOW + H))"; runit
a_no_card unexpected-listener; a_card monitor-unreadable; a_detail_has monitor-unreadable 'listeners'
[ -f "$STATE/ev.unexpected-listener" ] && ok || bad "a failed read must keep the open card's state"

# N7. more than eight: the first eight are named, the rest counted
t "listen-detail-capped"
setup; ss_base; LISTEN_ALLOW="$ALLOW"
for p in 7001 7002 7003 7004 7005 7006 7007 7008 7009 7010; do ss_add tcp LISTEN "0.0.0.0:$p" '0.0.0.0:*' app; done
runit; a_detail_has unexpected-listener '10 socket(s)'; a_detail_has unexpected-listener 'and 2 more'

# N8. the allowlist line firewall-snapshot.sh prints is accepted as it is
t "listen-snapshot-line"
setup; ss_base
LISTEN_ALLOW=$(awk '$5 !~ /^(127\.|\[::1\]|::1)/ { print $1 "/" $5 }' "$WORK/ss.out" | sort -u | tr '\n' ' ' | sed 's/ *$//')
runit; a_no_cards
grep -qF "awk '\$5 !~ /^(127\.|\[::1\]|::1)/ { print \$1 \"/\" \$5 }'" "$HERE/../firewall-snapshot.sh" && ok \
  || bad "firewall-snapshot.sh must print the allowlist line with the same filter"


# Check 13: container OS packages. Not a card: one `container-packages` report (info)
# per published container, for the hub to match. The fixtures are trimmed copies
# of real files: a Debian 12 dpkg status, a distroless status.d, an Alpine apk db.
CTR="$WORK/ctr"
IID_WEB="1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777000088889999"
IID_WEB2="2222aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777000088889999"
IID_DL="3333aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777000088889999"
IID_ALP="4444aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777000088889999"
IID_SCR="5555aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777000088889999"
ctr_ps()   { printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$CTR/ps"; }   # id names networks ports
ctr_add()  { mkdir -p "$CTR/$1/root"; printf '%s sha256:%s\n' "$2" "$3" > "$CTR/$1/inspect"; printf '%s\n' "$4" > "$CTR/created-$3"; }  # id ref iid created
ctr_put()  { mkdir -p "$CTR/$1/root$(dirname "$2")"; cat > "$CTR/$1/root$2"; }   # id path < content
cp_count() { n=$(grep -c "E=container-packages|S=triggered|" "$CARDS" 2>/dev/null); echo "${n:-0}"; }
a_cp_count()    { n=$(cp_count); [ "$n" = "$1" ] && ok || bad "expected $1 container-packages report(s), got $n ($(tr '\n' ' ' <"$CARDS"))"; }
a_cp_has()      { d=$(grep "E=container-packages|S=triggered|" "$CARDS" 2>/dev/null | grep -F "ctr=$1 " | tail -1 | sed 's/.*|D=//'); printf '%s' "$d" | grep -qF -- "$2" && ok || bad "expected the $1 list to contain '$2' (got: $d)"; }
a_cp_lacks()    { d=$(grep "E=container-packages|S=triggered|" "$CARDS" 2>/dev/null | grep -F "ctr=$1 " | tail -1 | sed 's/.*|D=//'); printf '%s' "$d" | grep -qF -- "$2" && bad "the $1 list must NOT contain '$2' (got: $d)" || ok; }
a_cp_none_for() { grep "E=container-packages|" "$CARDS" 2>/dev/null | grep -qF "ctr=$1 " && bad "unexpected report for container $1" || ok; }
a_cp_resolved() { grep "E=container-packages|S=resolved|" "$CARDS" 2>/dev/null | grep -qF "D=v=1 ctr=$1" && ok || bad "expected a resolved report for container $1 (got: $(tr '\n' ' ' <"$CARDS"))"; }
a_cp_info()     { grep "E=container-packages|S=triggered|" "$CARDS" 2>/dev/null | grep -qv "|V=info|" && bad "a container-packages report was not info" || ok; }

debian_web() { # id iid sshver
  ctr_add "$1" "ghcr.io/example/web:1.4@sha256:9999aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777000088881111" "$2" "2026-07-14T09:30:12.123456789Z"
  ctr_put "$1" /etc/os-release <<'EOF'
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
EOF
  ctr_put "$1" /var/lib/dpkg/status <<EOF
Package: bash
Essential: yes
Status: install ok installed
Priority: required
Section: shells
Installed-Size: 7163
Architecture: amd64
Source: bash (5.2.15-2)
Version: 5.2.15-2+b7
Description: GNU Bourne Again SHell
 Bash is an sh-compatible command language interpreter that executes
 commands read from the standard input or from a file.

Package: libc6
Status: install ok installed
Priority: optional
Section: libs
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.36-9+deb12u7
Description: GNU C Library: Shared libraries

Package: libc-bin
Essential: yes
Status: install ok installed
Architecture: amd64
Source: glibc
Version: 2.36-9+deb12u7
Description: GNU C Library: Binaries

Package: libsemanage2
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Source: libsemanage (3.4-1)
Version: 3.4-1+b5
Description: SELinux policy management library

Package: openssh-server
Status: install ok installed
Architecture: amd64
Multi-Arch: foreign
Source: openssh
Version: $3
Description: secure shell (SSH) server, for secure access from remote machines

Package: oldtool
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1
Description: removed, only its config is left

Package: zlib1g
Status: install ok installed
Architecture: amd64
Source: zlib
Version: 1:1.2.13.dfsg-1
Description: compression library - runtime
EOF
}

# C1. a published Debian container: one info report with its SOURCE packages (each
#     once, binNMU source versions, removed packages left out); an unpublished one: none
t "ctrpkg-debian-list"
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"
ctr_ps c1 web bridge "0.0.0.0:443->443/tcp, [::]:443->443/tcp"
ctr_add c2 "postgres:16" "$IID_DL" "2026-07-01T00:00:00Z"
ctr_ps c2 db bridge "5432/tcp"
runit; a_exit0; a_cp_count 1; a_cp_info; a_no_card monitor-unreadable
a_cp_has web "v=1 ctr=web img=ghcr.io/example/web:1.4@sha256:9999aaaa"
a_cp_has web "iid=1111aaaa2222 built=1784021412 os=debian osver=12 pm=dpkg more=0"
a_cp_has web "pkgs=bash@5.2.15-2,glibc@2.36-9+deb12u7,libsemanage@3.4-1,openssh@1:9.2p1-2+deb12u2,zlib@1:1.2.13.dfsg-1"
a_cp_lacks web "oldtool"
a_cp_none_for db

# C2. unchanged: not read or sent again until the resend interval, then sent once more
t "ctrpkg-unchanged-throttled"
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "127.0.0.1:8080->80/tcp"
runit; a_cp_count 1
: > "$CARDS"; : > "$CTR/cp.log"; RUN_NOW="$((NOW + H))"; runit
a_cp_count 0; [ -s "$CTR/cp.log" ] && bad "an unchanged container was read again" || ok
: > "$CARDS"; RUN_NOW="$((NOW + 21*H))"; runit; a_cp_count 1

# C3. recreated on a patched image: sent at once with the new versions
t "ctrpkg-new-image-resent"
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_cp_count 1
rm -rf "$CTR/c1" "$CTR/ps"; debian_web c9 "$IID_WEB2" "1:9.2p1-2+deb12u3"; ctr_ps c9 web bridge "0.0.0.0:443->443/tcp"
: > "$CARDS"; RUN_NOW="$((NOW + H))"; runit
a_cp_count 1; a_cp_has web "iid=2222aaaa2222"; a_cp_has web "openssh@1:9.2p1-2+deb12u3"
# recreated from the SAME image (new container id, same list): nothing to send
rm -rf "$CTR/ps"; mv "$CTR/c9" "$CTR/c10"; ctr_ps c10 web bridge "0.0.0.0:443->443/tcp"
: > "$CARDS"; RUN_NOW="$((NOW + 2*H))"; runit; a_cp_count 0

# C4. gone (stopped or no longer published): one resolved report, then nothing
t "ctrpkg-gone-resolved"
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_cp_count 1
: > "$CTR/ps"; : > "$CARDS"; RUN_NOW="$((NOW + H))"; runit
a_cp_resolved web; [ -f "$STATE/ctrpkg/web.sent" ] && bad "the gone container's state was kept" || ok
: > "$CARDS"; RUN_NOW="$((NOW + 2*H))"; runit; a_no_cards

# C5. distroless: no dpkg status file, one stanza file per package in status.d
#     (md5sums files beside them are skipped)
t "ctrpkg-distroless"
setup; DOCKERCMD="$BIN/mock-docker"
ctr_add d1 "gcr.io/distroless/base-debian12:nonroot" "$IID_DL" "2026-06-02T11:00:00Z"
printf 'PRETTY_NAME="Distroless"\nNAME="Debian GNU/Linux"\nID="debian"\nVERSION_ID="12"\nVERSION="Debian GNU/Linux 12 (bookworm)"\n' | ctr_put d1 /etc/os-release
printf 'Package: libc6\nVersion: 2.36-9+deb12u10\nArchitecture: amd64\nSource: glibc\nDescription: GNU C Library\n' | ctr_put d1 /var/lib/dpkg/status.d/libc6
printf 'Package: libssl3\nVersion: 3.0.15-1~deb12u1\nArchitecture: amd64\nSource: openssl\n' | ctr_put d1 /var/lib/dpkg/status.d/libssl3
printf '00112233445566778899aabbccddeeff  usr/lib/x86_64-linux-gnu/libssl.so.3\n' | ctr_put d1 /var/lib/dpkg/status.d/libssl3.md5sums
ctr_ps d1 app bridge "0.0.0.0:9000->9000/tcp"
runit; a_cp_count 1
a_cp_has app "os=debian osver=12 pm=dpkg"; a_cp_has app "pkgs=glibc@2.36-9+deb12u10,openssl@3.0.15-1~deb12u1"

# C6. Alpine: the ORIGIN of each package (OSV keys Alpine on it), each once; and a
#     host-network container counts as published
t "ctrpkg-alpine-origins"
setup; DOCKERCMD="$BIN/mock-docker"
ctr_add a1 "example/proxy:3.2-alpine" "$IID_ALP" "2026-03-11T08:00:00Z"
printf 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME="Alpine Linux v3.19"\n' | ctr_put a1 /etc/os-release
ctr_put a1 /lib/apk/db/installed <<'EOF'
P:musl
V:1.2.4_git20230717-r4
A:x86_64
S:407828
I:663552
T:the musl c library (libc) implementation
o:musl
m:Alpine maintainers

P:libcrypto3
V:3.1.4-r5
A:x86_64
T:Crypto library from openssl
o:openssl

P:libssl3
V:3.1.4-r5
A:x86_64
T:SSL shared libraries
o:openssl

P:busybox
V:1.36.1-r15
A:x86_64
o:busybox
EOF
ctr_ps a1 proxy host ""
runit; a_cp_count 1
a_cp_has proxy "os=alpine osver=3.19.1 pm=apk"; a_cp_has proxy "pkgs=busybox@1.36.1-r15,musl@1.2.4_git20230717-r4,openssl@3.1.4-r5"
a_cp_lacks proxy "libcrypto3"

# C7. an image with no package database or os-release (scratch): sent as pm=none, read
#     again each run (a failed copy must not hide one for a day), not sent again unchanged
t "ctrpkg-scratch-none"
setup; DOCKERCMD="$BIN/mock-docker"
ctr_add s1 "example/app:latest" "$IID_SCR" "2026-01-05T00:00:00Z"
ctr_ps s1 app bridge "0.0.0.0:9000->9000/tcp"
runit; a_cp_count 1; a_cp_has app "os=- osver=- pm=none more=0 pkgs=-"
: > "$CARDS"; : > "$CTR/cp.log"; RUN_NOW="$((NOW + H))"; runit
a_cp_count 0; [ -s "$CTR/cp.log" ] && ok || bad "a pm=none container was not read again"

# C8. the first lists wait for the arm delay when one is set
t "ctrpkg-arm-wait"
setup; DOCKERCMD="$BIN/mock-docker"; CP_ARM=7200
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_cp_count 0
RUN_NOW="$((NOW + H))"; runit; a_cp_count 0
RUN_NOW="$((NOW + 2*H))"; runit; a_cp_count 1

# C9. `docker ps` fails: nothing sent or resolved, folded into monitor-unreadable
t "ctrpkg-ps-unreadable"
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_cp_count 1
: > "$CTR/ps-fail"; : > "$CARDS"; RUN_NOW="$((NOW + 21*H))"; runit
a_cp_count 0; a_no_card container-packages
a_card monitor-unreadable; a_detail_has monitor-unreadable 'container-packages'

# C10. a container that cannot be inspected is skipped, never reported gone
t "ctrpkg-inspect-fails-kept"
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_cp_count 1
rm -f "$CTR/c1/inspect"; : > "$CARDS"; RUN_NOW="$((NOW + 21*H))"; runit
a_no_card container-packages; a_no_card monitor-unreadable

# C11. its own per-run cap (the alert cap is untouched): the rest go on the next run;
#      an undelivered list is sent again on the next run
t "ctrpkg-cap-and-retry"
setup; DOCKERCMD="$BIN/mock-docker"; CP_MAX=1
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
ctr_add s1 "example/app:latest" "$IID_SCR" "2026-01-05T00:00:00Z"; ctr_ps s1 app bridge "0.0.0.0:9000->9000/tcp"
runit; a_cp_count 1; a_cp_has web "pm=dpkg"
: > "$CARDS"; RUN_NOW="$((NOW + H))"; runit; a_cp_count 1; a_cp_has app "pm=none"
: > "$CARDS"; RUN_NOW="$((NOW + 2*H))"; runit; a_cp_count 0
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
: > "$WORK/report-fail"; runit; a_cp_count 0
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + H))"; runit; a_cp_count 1

# C11b. a list the hub refuses for this key (HTTP 403, a dm= key) is not read and sent
#       again every run: one log line, then it waits for the 20h resend interval. A
#       container that goes away before any list was stored needs no resolved report.
t "ctrpkg-refused-waits"
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:1.0-1"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
: > "$WORK/report-refused"
runit; a_exit0; a_cp_count 0; a_ev_attempts container-packages 1
grep -qF "the hub refused the package list of container web for this key (HTTP 403" "$WORK/stderr" && ok \
  || bad "expected one log line for the refusal (got: $(tr '\n' ' ' < "$WORK/stderr"))"
[ -f "$STATE/ctrpkg/web.sent" ] && bad "a refused list must not be marked sent" || ok
: > "$CTR/cp.log"; RUN_NOW="$((NOW + H))"; runit; a_ev_attempts container-packages 1
[ -s "$CTR/cp.log" ] && bad "a refused, unchanged container was read again" || ok
grep -q "the hub refused" "$WORK/stderr" && bad "a refusal is logged once, not every run" || ok
RUN_NOW="$((NOW + 21*H))"; runit; a_ev_attempts container-packages 2
: > "$CTR/ps"; RUN_NOW="$((NOW + 22*H))"; runit; a_ev_attempts container-packages 2
[ -f "$STATE/ctrpkg/web.refused" ] && bad "the refusal of a gone container must be dropped" || ok
# a stored list whose resolved report is refused: tried once, then it waits too
setup; DOCKERCMD="$BIN/mock-docker"
debian_web c1 "$IID_WEB" "1:1.0-1"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_cp_count 1
: > "$CTR/ps"; : > "$WORK/report-refused"; : > "$WORK/attempts"
RUN_NOW="$((NOW + H))"; runit; a_ev_attempts container-packages 1
RUN_NOW="$((NOW + 2*H))"; runit; a_ev_attempts container-packages 1
[ -f "$STATE/ctrpkg/web.sent" ] && ok || bad "the resolved report stays owed"
rm -f "$WORK/report-refused"; : > "$CARDS"
RUN_NOW="$((NOW + 22*H))"; runit; a_cp_resolved web
[ -f "$STATE/ctrpkg/web.sent" ] || [ -f "$STATE/ctrpkg/web.refused" ] && bad "a delivered resolve clears both records" || ok

# C12. switched off, or no Docker: nothing
t "ctrpkg-disabled"
setup; DOCKERCMD="$BIN/mock-docker"; CP_ENABLE=0
debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_no_cards
setup; debian_web c1 "$IID_WEB" "1:9.2p1-2+deb12u2"; ctr_ps c1 web bridge "0.0.0.0:443->443/tcp"
runit; a_no_cards

# ===========================================================================
# Delivery: only a 2xx counts as sent. A report that was not delivered (an error answer,
# no answer, over the per-run cap) changes no state, so the next run sends it again; a
# delivered one is never sent twice.
a_attempts()   { n=$(wc -l < "$WORK/attempts" 2>/dev/null | tr -d ' '); [ "${n:-0}" = "$1" ] && ok || bad "expected $1 post attempt(s), got ${n:-0}: $(tr '\n' ' ' < "$WORK/attempts" 2>/dev/null)"; }
a_state()      { [ -f "$STATE/ev.$1" ] && ok || bad "expected the state file ev.$1"; }
a_no_state()   { [ -f "$STATE/ev.$1" ] && bad "ev.$1 must not exist (got: $(cat "$STATE/ev.$1"))" || ok; }
a_state_line() { l=$(cat "$STATE/ev.$1" 2>/dev/null); [ "$l" = "$2" ] && ok || bad "expected ev.$1 to read '$2' (got: '$l')"; }
a_log_has()    { grep -qF -- "$1" "$WORK/stderr" && ok || bad "expected the log to say '$1' (got: $(tr '\n' ' ' < "$WORK/stderr"))"; }

# D1. a raise the hub refused (an unknown key, a 503) is sent again on the next run, and
#     once delivered it is not sent again
t "delivery-raise-retried"
setup; ubuntu
: > "$WORK/report-fail"
runit; a_exit0; a_no_card livepatch-off; a_attempts 1; a_no_state livepatch-off; a_log_has "post failed"
rm -f "$WORK/report-fail"; : > "$CARDS"; RUN_NOW="$((NOW + 1800))"; runit
a_card_state livepatch-off triggered; a_state_line livepatch-off "warning $((NOW + 1800))"
: > "$CARDS"; RUN_NOW="$((NOW + 3600))"; runit; a_no_cards

# D2. a raise that never got out, then the condition cleared: nothing was posted, so
#     nothing is resolved
t "delivery-raise-failed-then-cleared"
setup; ubuntu
: > "$WORK/report-fail"; runit; a_no_cards
rm -f "$WORK/report-fail"; lp_ok; RUN_NOW="$((NOW + 1800))"; runit
a_no_cards; a_no_state livepatch-off

# D3. a resolve that failed keeps the state, so `resolved` is sent again on the next run
t "delivery-resolve-retried"
setup; ubuntu
runit; a_card_state livepatch-off triggered
lp_ok; : > "$WORK/report-fail"; : > "$CARDS"; RUN_NOW="$((NOW + 1800))"; runit
a_no_cards; a_state livepatch-off
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + 3600))"; runit
a_card_state livepatch-off resolved; a_no_state livepatch-off
: > "$CARDS"; RUN_NOW="$((NOW + 5400))"; runit; a_no_cards

# D4. a re-surface that failed keeps the old stamp: the next run sends it, then it is
#     throttled again from that send
t "delivery-resurface-retried"
setup; ubuntu
runit; a_card livepatch-off
: > "$CARDS"; : > "$WORK/report-fail"; RUN_NOW="$((NOW + 6*H))"; runit
a_no_cards; a_state_line livepatch-off "warning $NOW"
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + 6*H + 1800))"; runit
a_card_state livepatch-off triggered; a_state_line livepatch-off "warning $((NOW + 6*H + 1800))"
: > "$CARDS"; RUN_NOW="$((NOW + 7*H))"; runit; a_no_cards

# D5. a severity change that failed is sent on the next run at the severity of THAT run
t "delivery-severity-change-retried"
setup
mk_sim "$SIMFILE" somelib 2.0
cve_line somelib medium CVE-2026-2 https://ubuntu.com/security/CVE-2026-2
seed_clock "$((NOW - 100000)) 1  "
runit; a_card_sev security-updates warning
cve_line somelib high CVE-2026-3 https://ubuntu.com/security/CVE-2026-3
: > "$CARDS"; : > "$WORK/report-fail"; RUN_NOW="$((NOW + 1800))"; runit
a_no_cards; a_state_line security-updates "warning $NOW"
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + 3600))"; runit
a_card_sev security-updates critical; a_state_line security-updates "critical $((NOW + 3600))"
: > "$CARDS"; RUN_NOW="$((NOW + 5400))"; runit; a_no_card security-updates

# D6. over the per-run cap: the overflow is logged, and the next run sends the rest
t "delivery-cap-rest-next-run"
setup; ubuntu; MAXP=1
chmod 0777 "$SP_ROOT"                                  # check 6 raises too, before check 9
runit; a_card script-path-writable; a_no_card livepatch-off; a_no_state livepatch-off
a_log_has "per-run post cap (1) hit; 1 report(s) suppressed this run"
: > "$CARDS"; RUN_NOW="$((NOW + 1800))"; runit; a_card livepatch-off; a_no_card script-path-writable
: > "$CARDS"; RUN_NOW="$((NOW + 3600))"; runit; a_no_cards
chmod 0755 "$SP_ROOT"

# D7. no answer at all: one attempt, the rest of the run waits (no timeout per report),
#     and the next run sends them all
t "delivery-no-answer-defers-the-rest"
setup; ubuntu
chmod 0777 "$SP_ROOT"
: > "$WORK/report-down"
runit; a_exit0; a_no_cards; a_attempts 1; a_no_state script-path-writable; a_no_state livepatch-off
a_log_has "the hub did not answer; 1 more report(s) wait for the next run"
rm -f "$WORK/report-down"; RUN_NOW="$((NOW + 1800))"; runit
a_card script-path-writable; a_card livepatch-off
chmod 0755 "$SP_ROOT"

# D8. the monitor-unreadable fold: a raise that failed goes on the next run, and its
#     resolve goes once every check reads again
t "delivery-unreadable-fold-retried"
setup; ubuntu; LPCMD="$BIN/mock-livepatch"; printf 'error: cannot connect to the daemon\n' > "$LPFILE"
: > "$WORK/report-fail"; runit; a_no_cards; a_no_state monitor-unreadable
rm -f "$WORK/report-fail"; RUN_NOW="$((NOW + 1800))"; runit
a_card_state monitor-unreadable triggered; a_detail_has monitor-unreadable 'livepatch'
lp_ok; : > "$CARDS"; RUN_NOW="$((NOW + 3600))"; runit
a_card_state monitor-unreadable resolved; a_no_card livepatch-off; a_no_state monitor-unreadable

# ===========================================================================
echo ""
echo "security-report: $PASS passed, $FAIL failed"
rm -rf "$WORK" 2>/dev/null || :
[ "$FAIL" -eq 0 ]
