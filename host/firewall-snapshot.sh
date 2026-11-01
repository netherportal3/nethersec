#!/usr/bin/env bash
# firewall-snapshot.sh: print this box's firewall setup as stable text, so it can be
# committed and diffed. Read-only: it changes nothing.
#
# Covers ufw, iptables and ip6tables (Docker's rules included), every other nftables
# table (fail2ban, nethersec_ipopt, nethersec_flood, ...), fail2ban jail names, the
# network sysctls that act as a firewall, and the sockets listening on a non-loopback
# address. Counters and set elements are stripped (fail2ban's sets hold the IPs it
# banned, which change every minute and are not ours to keep), so two runs on an
# unchanged box print the same text.
#
#   sudo bash /opt/nethersec/firewall-snapshot.sh > box.txt
#
# Keep the snapshots somewhere private, never in a public repo: they list open ports
# and allow-lists. The listeners section comes last, and the last line of the output is
# the box's HOSTSEC_LISTEN_ALLOW for check 12 of security-report.sh (`tail -n 1` gives
# it), so anything new goes above that section.
set -uo pipefail

section() { printf '\n## %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

. /etc/os-release 2>/dev/null || true
printf '# firewall snapshot: %s (%s %s, kernel %s)\n' "$(hostname)" "${NAME:-?}" "${VERSION_ID:-?}" "$(uname -r)"

section "ufw"
if have ufw; then ufw status verbose 2>&1; else echo "not installed"; fi

section "iptables-save (IPv4)"
if have iptables-save; then
  iptables-save 2>&1 | grep -v '^#' | sed -E 's/ \[[0-9]+:[0-9]+\]$//'
else echo "not installed"; fi

section "ip6tables-save (IPv6)"
if have ip6tables-save; then
  ip6tables-save 2>&1 | grep -v '^#' | sed -E 's/ \[[0-9]+:[0-9]+\]$//'
else echo "not installed"; fi

section "nftables tables"
if have nft; then
  nft list tables 2>&1
  # The ip/ip6 filter, nat, raw and mangle tables are the iptables view above.
  nft list tables 2>/dev/null | while read -r _ fam name; do
    case "$fam:$name" in
      ip:filter|ip:nat|ip:raw|ip:mangle|ip:security|ip6:filter|ip6:nat|ip6:raw|ip6:mangle|ip6:security) continue ;;
    esac
    printf '\n### table %s %s\n' "$fam" "$name"
    nft -s list table "$fam" "$name" 2>&1 | awk '
      /elements = \{/ { skip = 1 }
      skip { if ($0 ~ /\}/) { skip = 0; print "\t\telements = { (stripped) }" } ; next }
      { print }'
  done
else echo "nft not installed"; fi

section "fail2ban jails"
if have fail2ban-client; then
  fail2ban-client status 2>&1 | sed -n 's/.*Jail list:[[:space:]]*//p'
  for f in /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.d/*.local; do
    [ -f "$f" ] || continue
    printf -- '--- %s\n' "$f"
    grep -vE '^[[:space:]]*(#|;|$)' "$f"
  done
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -qx mailserver; then
  echo "host: not installed; mailserver container: $(docker exec mailserver fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p')"
else echo "not installed"; fi

section "sysctls"
for k in net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_source_route \
         net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.tcp_syncookies \
         net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.tcp_migrate_req net.mptcp.enabled \
         net.ipv6.conf.all.accept_ra net.ipv6.conf.all.forwarding; do
  printf '%s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo '?')"
done

section "systemd firewall units"
for u in ufw.service nftables.service netfilter-persistent.service fail2ban.service nethersec-ipv4-options-drop.service; do
  en=$(systemctl is-enabled "$u" 2>/dev/null | head -n 1); ac=$(systemctl is-active "$u" 2>/dev/null | head -n 1)
  printf '%s: %s / %s\n' "$u" "${en:-absent}" "${ac:-inactive}"
done

# The listeners come last, so the allowlist line below is the last line of the output.
section "listening on a non-loopback address"
ss -Htulnp 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\]|::1)/ {
  proc = $7; sub(/^users:\(\("/, "", proc); sub(/".*/, "", proc)
  print $1, $5, proc }' | sort -u
# The same sockets as the allowlist of security-report.sh's listener check, ready for
# /etc/nethersec/report.env. Put * for a port that changes on every restart.
printf 'HOSTSEC_LISTEN_ALLOW="%s"\n' "$(ss -Htuln 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\]|::1)/ { print $1 "/" $5 }' \
  | sort -u | tr '\n' ' ' | sed 's/ *$//')"
# Nothing may print after the line above: it is the last line of the output.
