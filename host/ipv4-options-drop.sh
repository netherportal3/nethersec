#!/usr/bin/env bash
# ipv4-options-drop.sh: drop inbound IPv4 TCP packets that carry IP options. Idempotent.
#
# Why: CVE-2026-98432 (Linux IPv4 TCP use-after-free, CVSS 9.8, every kernel since 4.4)
# is reached only through a SYN that carries IPv4 options (Record
# Route or Timestamp). The kernel keeps a copy of those options with the half-open
# connection, and a race frees that copy while another CPU still reads it. A SYN with no
# IP options never gets the copy, so there is nothing to free. No normal client sends IP
# options and most networks drop them, so dropping them here removes the trigger for every
# listener on the box, plain TCP and Multipath TCP alike, and restarts nothing. Keep it
# after the fixed kernel ships too: a server has no use for IP options.
#
# What it does: writes the nftables table below to /etc/nethersec/ipv4-options-drop.nft,
# checks it with `nft -c`, then installs and starts nethersec-ipv4-options-drop.service,
# which loads it now and again at every boot. The table is its own (`ip nethersec_ipopt`,
# at the raw prerouting hook, before Docker's rules), so the Docker, ufw and fail2ban
# tables are never touched. IPv6 is not affected by the bug and is left alone.
#
#   sudo bash /opt/nethersec/ipv4-options-drop.sh            # turn it on
#   sudo bash /opt/nethersec/ipv4-options-drop.sh --check    # report only
#   sudo bash /opt/nethersec/ipv4-options-drop.sh --remove   # take it off again
#
# --check exits 0 when the table is loaded and the unit is enabled, 1 otherwise, and
# prints the drop counter (packets that carried IP options and were dropped).
#
# Env seams (the offline harness test/ipv4-options-drop.test.sh sets them):
#   HOSTSEC_NFT_CMD        (default: nft)
#   HOSTSEC_SYSTEMCTL_CMD  (default: systemctl)
#   HOSTSEC_ETC_DIR        (default: /etc/nethersec)
#   HOSTSEC_UNIT_DIR       (default: /etc/systemd/system)
set -euo pipefail

NFT="${HOSTSEC_NFT_CMD:-nft}"
SYSTEMCTL="${HOSTSEC_SYSTEMCTL_CMD:-systemctl}"
ETC_DIR="${HOSTSEC_ETC_DIR:-/etc/nethersec}"
UNIT_DIR="${HOSTSEC_UNIT_DIR:-/etc/systemd/system}"
TABLE="nethersec_ipopt"
UNIT="nethersec-ipv4-options-drop.service"
RULES="$ETC_DIR/ipv4-options-drop.nft"

MODE=apply
case "${1:-}" in
  --check) MODE=check ;;
  --remove) MODE=remove ;;
  '') ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "ipv4-options-drop: unknown arg '$1'" >&2; exit 2 ;;
esac

NFT_PATH=$(command -v "$NFT" 2>/dev/null || true)
if [ -z "$NFT_PATH" ]; then
  echo "ipv4-options-drop: nft is not installed here (apt-get install nftables)." >&2
  exit 1
fi

if ! "$NFT" list tables >/dev/null 2>&1; then
  echo "ipv4-options-drop: cannot read the nftables ruleset (run as root)." >&2
  exit 1
fi

table_loaded() { "$NFT" list table ip "$TABLE" >/dev/null 2>&1; }
drop_count() {
  "$NFT" list counter ip "$TABLE" dropped 2>/dev/null | awk '/packets/ {for (i = 1; i < NF; i++) if ($i == "packets") print $(i + 1)}'
}

if [ "$MODE" = check ]; then
  rc=0
  if table_loaded; then
    echo "ipv4-options-drop: table loaded, $(drop_count || echo '?') packets dropped since it was loaded."
  else
    echo "ipv4-options-drop: table NOT loaded. Turn it on: sudo bash $0"; rc=1
  fi
  if [ "$("$SYSTEMCTL" is-enabled "$UNIT" 2>/dev/null || true)" = enabled ]; then
    echo "ipv4-options-drop: $UNIT is enabled, so it loads again at boot."
  else
    echo "ipv4-options-drop: $UNIT is NOT enabled, so a reboot would drop the table."; rc=1
  fi
  exit "$rc"
fi

install -d -m 0755 "$ETC_DIR" "$UNIT_DIR" 2>/dev/null || true
if [ ! -w "$ETC_DIR" ] || [ ! -w "$UNIT_DIR" ]; then
  echo "ipv4-options-drop: cannot write $ETC_DIR or $UNIT_DIR (run as root)." >&2
  exit 1
fi

if [ "$MODE" = remove ]; then
  "$SYSTEMCTL" disable --now "$UNIT" >/dev/null 2>&1 || true
  if table_loaded; then "$NFT" delete table ip "$TABLE"; fi
  rm -f "$UNIT_DIR/$UNIT" "$RULES"
  "$SYSTEMCTL" daemon-reload
  if table_loaded; then
    echo "ipv4-options-drop: the table is still loaded after removal. Check 'nft list tables'." >&2
    exit 1
  fi
  echo "ipv4-options-drop: removed. IPv4 packets with IP options are accepted again."
  exit 0
fi

tmp="$RULES.tmp.$$"
trap 'rm -f "$tmp"' EXIT
# The first two lines make a reload replace the table instead of adding a second rule.
cat > "$tmp" <<EOF
# Written by nethersec (/opt/nethersec/ipv4-options-drop.sh). Edit the script, not this file.
table ip $TABLE
delete table ip $TABLE
table ip $TABLE {
  counter dropped {}
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    ip hdrlength != 5 meta l4proto tcp counter name "dropped" drop
  }
}
EOF
chmod 0644 "$tmp"
if ! "$NFT" -c -f "$tmp" >/dev/null 2>&1; then
  echo "ipv4-options-drop: nft rejected the rules; nothing was changed:" >&2
  "$NFT" -c -f "$tmp" >&2 || true
  exit 1
fi
mv -f "$tmp" "$RULES"
trap - EXIT

# Ordered like the stock nftables.service: before the network comes up, so a box never
# accepts connections at boot without the table.
cat > "$UNIT_DIR/$UNIT" <<EOF
[Unit]
Description=nethersec: drop inbound IPv4 TCP packets that carry IP options (CVE-2026-98432)
Wants=network-pre.target
Before=network-pre.target shutdown.target docker.service
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NFT_PATH -f $RULES
ExecReload=$NFT_PATH -f $RULES
ExecStop=$NFT_PATH delete table ip $TABLE

[Install]
WantedBy=sysinit.target
EOF
chmod 0644 "$UNIT_DIR/$UNIT"

"$SYSTEMCTL" daemon-reload
"$SYSTEMCTL" enable "$UNIT" >/dev/null 2>&1
"$SYSTEMCTL" restart "$UNIT"

if table_loaded; then
  echo "ipv4-options-drop: on. Inbound IPv4 TCP packets with IP options are dropped; nothing was restarted."
  exit 0
fi
echo "ipv4-options-drop: $UNIT ran but the table is not loaded. Check 'journalctl -u $UNIT'." >&2
exit 1
