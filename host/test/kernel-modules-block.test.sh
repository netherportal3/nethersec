#!/usr/bin/env sh
# kernel-modules-block.test.sh: offline harness for kernel-modules-block.sh. Points the
# script at a scratch modprobe.d and a fake /proc/modules through its env seams, so it
# needs no root and changes nothing on the machine. Asserts:
#   - apply writes one `install <module> /bin/false` line per listed module
#   - a module loaded right now is left out and named, never blocked
#   - --check passes only when every listed module that is not loaded is blocked,
#     names a loaded one, and writes nothing
#   - a missing or partial file fails --check
#   - re-running apply is safe and drops a module that became loaded
#   - --remove deletes the file, and is fine when there is none
#   - an unreadable /proc/modules or modprobe.d is an error
#
#   sh host/test/kernel-modules-block.test.sh
#
# Exit 0 = all asserts passed.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SCRIPT="$HERE/../kernel-modules-block.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT"; exit 2; }
command -v bash >/dev/null 2>&1 || { echo "kernel-modules-block.test: bash is required"; exit 2; }

WORK=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/kmb.$$"); mkdir -p "$WORK"
DIR="$WORK/modprobe.d"
MODS="$WORK/modules"
CONF="$DIR/nethersec-blocked-modules.conf"

PASS=0; FAIL=0; CUR=""
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$CUR]: $1"; }
t()   { CUR="$1"; }

# A /proc/modules with the given module names loaded.
loaded() {
  : > "$MODS"
  for m in "$@"; do echo "$m 16384 0 - Live 0x0000000000000000" >> "$MODS"; done
}
setup() { rm -rf "$DIR"; mkdir -p "$DIR"; loaded overlay btrfs veth; }
run() {
  HOSTSEC_MODPROBE_DIR="$DIR" HOSTSEC_PROC_MODULES="$MODS" \
    bash "$SCRIPT" "$@" > "$WORK/out" 2>&1
  RC=$?
}
blocks() { grep -qxF "install $1 /bin/false" "$CONF"; }

t "apply blocks the listed modules"
setup; run
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"
[ -f "$CONF" ] && ok || bad "no file written"
for m in nfsd sunrpc ceph sctp openvswitch ip_vs smc rdma_rxe siw ib_srpt rtrs_server rpcrdma nvmet_tcp ksmbd cifs dccp tipc bluetooth; do
  blocks "$m" && ok || bad "$m not blocked"
done
[ "$(grep -c '^install ' "$CONF")" -ge 80 ] && ok || bad "fewer lines than expected: $(grep -c '^install ' "$CONF")"
grep -v '^#' "$CONF" | grep -qv '^install [a-z0-9_]* /bin/false$' && bad "a line is not an install-false line" || ok
blocks btrfs && bad "blocked btrfs, which is not on the list" || ok
ls "$DIR" | grep -q tmp && bad "temp file left behind" || ok

t "the list leaves out modules the boxes need"
for m in overlay bridge veth br_netfilter nf_conntrack nf_tables xt_conntrack tls tun vxlan wireguard ib_core btrfs mlx5_core virtio_net xfrm_user esp4 nf_conntrack_ftp ext4; do
  blocks "$m" && bad "blocks $m" || ok
done

t "a loaded module is left out and named"
setup; loaded overlay sctp; run
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"
blocks sctp && bad "blocked the loaded sctp" || ok
blocks tipc && ok || bad "tipc not blocked"
grep -q 'left out: sctp' "$WORK/out" && ok || bad "sctp not named: $(cat "$WORK/out")"

t "--check passes when on, and writes nothing"
setup; run; cp "$CONF" "$WORK/conf.before"
run --check
[ "$RC" -eq 0 ] && grep -q 'kernel-modules-block: on, ' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"
cmp -s "$CONF" "$WORK/conf.before" && ok || bad "--check rewrote the file"

t "--check names a listed module that is loaded, and still passes"
loaded overlay sctp; run --check
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"
grep -q 'loaded here, so not blocked: sctp' "$WORK/out" && ok || bad "sctp not named: $(cat "$WORK/out")"

t "--check fails when the file is missing"
setup; run --check
[ "$RC" -eq 1 ] && grep -q 'is missing' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"
[ -f "$CONF" ] && bad "--check wrote the file" || ok

t "--check fails when a module is missing from the file"
setup; run; grep -vxF 'install tipc /bin/false' "$CONF" > "$WORK/c" && cp "$WORK/c" "$CONF"
run --check
[ "$RC" -eq 1 ] && grep -q 'not blocked yet: tipc' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"

t "re-running apply is safe and drops a module that became loaded"
setup; run; loaded overlay dccp; run
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"
blocks dccp && bad "still blocks the now-loaded dccp" || ok
blocks sctp && ok || bad "sctp lost on the re-run"
[ "$(grep -c '^install sctp ' "$CONF")" -eq 1 ] && ok || bad "duplicate lines after a re-run"

t "--remove deletes the file"
setup; run; run --remove
[ "$RC" -eq 0 ] && [ ! -f "$CONF" ] && ok || bad "exit $RC, file left: $(cat "$WORK/out")"

t "--remove when nothing is installed is fine"
setup; run --remove
[ "$RC" -eq 0 ] && ok || bad "exit $RC: $(cat "$WORK/out")"

t "an unreadable /proc/modules is an error"
setup; rm -f "$MODS"; run
[ "$RC" -eq 1 ] && grep -q 'cannot read' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"
[ -f "$CONF" ] && bad "wrote the file anyway" || ok

t "an unwritable modprobe.d is an error"
# Root, and a filesystem that ignores the mode bits, can still write: skip there.
setup; chmod 0555 "$DIR"
if [ ! -w "$DIR" ]; then
  run
  [ "$RC" -eq 1 ] && grep -q 'run as root' "$WORK/out" && ok || bad "exit $RC: $(cat "$WORK/out")"
fi
chmod 0755 "$DIR"

t "unknown arg"
setup; run --bogus
[ "$RC" -eq 2 ] && ok || bad "exit $RC"

rm -rf "$WORK"
echo "kernel-modules-block.test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
