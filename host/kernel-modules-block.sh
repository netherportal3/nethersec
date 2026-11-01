#!/usr/bin/env bash
# kernel-modules-block.sh: stop the kernel from loading network modules a typical web
# server never uses. Idempotent.
#
# Why: many critical network kernel CVEs sit in modules a typical web server never loads
# (NFS and SunRPC, Ceph, SCTP, SMB, the RDMA stack, NVMe and iSCSI over the network, Open
# vSwitch, IPVS, MPLS). A module that is not loaded cannot be
# reached, but the kernel loads many of them on demand: any process, a container's
# included, that opens a socket of the family loads the module behind it, and from then
# on it parses packets from the network. Blocking the load closes that path for every bug
# in those modules, fixed or not, with no reboot. The rest of those CVEs are in the core
# (TCP, UDP, fragments, the bridge and veth Docker uses) and need the fixed kernel.
#
# What it does: writes /etc/modprobe.d/nethersec-blocked-modules.conf with an
# `install <module> /bin/false` line per module in BLOCKED below, so modprobe refuses an
# explicit load and an automatic one alike. A module loaded on this box right now is left
# out and named, so nothing running loses a module. Nothing is unloaded and nothing
# restarts. The list leaves out hardware drivers (a box moved to hardware with that NIC
# would lose its network), the tunnels and IPsec that Docker and VPN clients may use,
# and the conntrack helpers other than SIP's (ufw may load the FTP one).
#
#   sudo bash /opt/nethersec/kernel-modules-block.sh            # turn it on
#   sudo bash /opt/nethersec/kernel-modules-block.sh --check    # report only
#   sudo bash /opt/nethersec/kernel-modules-block.sh --remove   # take it off again
#
# --check exits 0 when the file is in place and blocks every module in BLOCKED that is
# not loaded here, 1 otherwise. It names any module in BLOCKED that is loaded.
#
# Env seams (the offline harness test/kernel-modules-block.test.sh sets them):
#   HOSTSEC_MODPROBE_DIR   (default: /etc/modprobe.d)
#   HOSTSEC_PROC_MODULES   (default: /proc/modules)
set -euo pipefail

MODPROBE_DIR="${HOSTSEC_MODPROBE_DIR:-/etc/modprobe.d}"
PROC_MODULES="${HOSTSEC_PROC_MODULES:-/proc/modules}"
CONF="$MODPROBE_DIR/nethersec-blocked-modules.conf"

# Check the list against your own boxes before you rely on it: `grep -c '^<name> '
# /proc/modules` prints 1 for a loaded module. This script already leaves loaded ones
# out, but a module your box loads only now and then (an NFS mount at backup time, say)
# would be blocked the next time it is wanted. On Ubuntu 24.04 the RDMA, L2TP and some
# other modules are not installed at all (they ship in linux-modules-extra); the line
# costs nothing there and covers a later install.
BLOCKED=(
  # Subsystems with critical network kernel CVEs.
  nfsd nfs nfsv3 nfsv4 lockd sunrpc nfs_acl auth_rpcgss rpcsec_gss_krb5 rpcrdma
  ceph libceph rbd ksmbd cifs ocfs2 ntfs3
  sctp openvswitch nf_conntrack_sip nf_nat_sip ip_vs smc smc_diag
  rdma_rxe siw ib_srpt ib_isert ib_iser rtrs_server rtrs_client rnbd_server rnbd_client
  nvmet nvmet_tcp nvmet_rdma nvme_tcp iscsi_tcp libiscsi_tcp target_core_mod iscsi_target_mod
  mpls_router mpls_iptunnel mpls_gso ip6_tunnel macvlan ipvlan ovpn x25
  # Other socket families any process can load on demand, rarely used on a server.
  dccp tipc rds rds_tcp rds_rdma l2tp_core l2tp_ip l2tp_ip6 l2tp_ppp l2tp_eth l2tp_netlink
  pppoe pptp atm appletalk ax25 netrom rose phonet rxrpc kafs caif qrtr
  can can_raw can_bcm can_gw can_isotp can_j1939 ieee802154 ieee802154_socket 6lowpan
  bluetooth nfc hsr batman_adv gtp n_hdlc
)

MODE=apply
case "${1:-}" in
  --check) MODE=check ;;
  --remove) MODE=remove ;;
  '') ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "kernel-modules-block: unknown arg '$1'" >&2; exit 2 ;;
esac

if [ ! -r "$PROC_MODULES" ]; then
  echo "kernel-modules-block: cannot read $PROC_MODULES." >&2
  exit 1
fi
# /proc/modules names a module with underscores, as modprobe matches it.
loaded_now=" $(awk '{print $1}' "$PROC_MODULES" | tr '\n' ' ') "
is_loaded() { case "$loaded_now" in *" $1 "*) return 0 ;; esac; return 1; }

want=()
skipped=()
for m in "${BLOCKED[@]}"; do
  if is_loaded "$m"; then skipped+=("$m"); else want+=("$m"); fi
done

if [ "$MODE" = check ]; then
  rc=0
  if [ ! -f "$CONF" ]; then
    echo "kernel-modules-block: $CONF is missing, so the kernel can load every module on the list. Turn it on: sudo bash $0"
    exit 1
  fi
  missing=()
  for m in "${want[@]}"; do
    grep -qxF "install $m /bin/false" "$CONF" || missing+=("$m")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "kernel-modules-block: not blocked yet: ${missing[*]}. Refresh it: sudo bash $0"; rc=1
  else
    echo "kernel-modules-block: on, ${#want[@]} modules blocked."
  fi
  if [ "${#skipped[@]}" -gt 0 ]; then
    echo "kernel-modules-block: loaded here, so not blocked: ${skipped[*]}"
  fi
  exit "$rc"
fi

# Create it only when missing: `install -d -m` would also re-mode an existing one.
[ -d "$MODPROBE_DIR" ] || install -d -m 0755 "$MODPROBE_DIR" 2>/dev/null || true
if [ ! -w "$MODPROBE_DIR" ]; then
  echo "kernel-modules-block: cannot write $MODPROBE_DIR (run as root)." >&2
  exit 1
fi

if [ "$MODE" = remove ]; then
  rm -f "$CONF"
  echo "kernel-modules-block: removed. The kernel can load these modules again."
  exit 0
fi

tmp="$CONF.tmp.$$"
trap 'rm -f "$tmp"' EXIT
{
  echo "# Written by nethersec (/opt/nethersec/kernel-modules-block.sh). Edit the script, not this file."
  echo "# Network modules this box does not use: modprobe refuses to load them, on request or on demand."
  for m in "${want[@]}"; do echo "install $m /bin/false"; done
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$CONF"
trap - EXIT

echo "kernel-modules-block: on. ${#want[@]} modules blocked; nothing was unloaded or restarted."
if [ "${#skipped[@]}" -gt 0 ]; then
  echo "kernel-modules-block: loaded here, so left out: ${skipped[*]}"
fi
exit 0
