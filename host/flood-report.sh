#!/usr/bin/env sh
# flood-report.sh: the box-side network / HTTP FLOOD (DDoS) detector.
#
# A CDN or an edge firewall only sees traffic that goes through it. Anyone who learns
# a box's IP can reach it directly: an HTTP flood, an SMTP connection flood, or a
# pre-auth TCP/SYN flood that pages nobody. This reads the signals the box itself can
# see about that traffic.
#
# It reports through nethersec-report.sh --kind security, like the host detector: a
# quiet card by default, a page when a check is set to --severity critical. It shares
# security-report.sh's transition engine (raise once, resolve once, throttled
# re-surface, per-run post cap, monitor-unreadable fold, kill switch, always exit 0)
# but runs on its OWN fast timer (~1 min) because a live flood cannot wait for the
# 30-min host-security cadence.
#
# Checks (each posts on a STATE TRANSITION, not every run):
#   1. Connection flood  ; event `conn-flood`. conntrack table saturation
#      (nf_conntrack_count/_max), a SYN-recv half-open burst (a SYN flood), or one
#      source IP dominating the established connections (a connection flood). Warning
#      (quiet) by default; the dominant source IP is enriched into the card.
#   2. Network volume     ; event `net-flood`. Inbound packets/sec + bits/sec from
#      /proc/net/dev over the run window (the volumetric L3/L4 signal a box can see).
#      Warning by default. No single source (volume, not a picked IP), so never mitigated.
#   3. HTTP request flood ; event `http-flood`. Per-client request rate from the Caddy
#      access log (JSON). Raises when total >= min AND the top client holds the share
#      (named, and blockable), or when the total rate alone reaches TOTAL_PER_MIN (no
#      single source, never blocked). Honors Cf-Connecting-Ip when the request came
#      from a Cloudflare range (so it counts the real client, not Cloudflare). Every
#      request counts; a top client in the CDN ranges or with good-bot UAs is only
#      exempt from a block. Warning by default. Inert on a box with no Caddy container.
#   4. SMTP connect burst ; event `smtp-flood`. postfix `connect from` rate from the
#      mailserver container logs over the window; the top source IP is named on the card
#      when it holds HOSTSEC_FLOOD_SMTP_SHARE_PCT of the connects. Warning by default.
#      Never mitigated. Inert on a box with no mailserver container.
#
# MITIGATION (ships DARK; dry-run by default, exactly like the release-age applier):
#   When a check confirms ONE dominant IPv4 source (conn-flood established, or
#   http-flood), and HOSTSEC_FLOOD_MITIGATE=1, this adds a self-expiring nftables drop
#   for that IP (a dedicated `inet nethersec_flood` table, prerouting hook priority
#   -300 so it runs BEFORE Docker's chains, a `flood_drop` set with per-element
#   timeout). It is guarded three ways; the good-bot/CDN allowlist (never Cloudflare/
#   Fastly/Discordbot), your never-drop list HOSTSEC_FLOOD_ALLOW_IPS (your own app's
#   egress, uptime monitors, your admin IP), and a per-hour cap; and every decline falls through to the human
#   alert (worst case: alerted, not blocked). Default HOSTSEC_FLOOD_MITIGATE=0 logs the
#   would-drop set only. Panic undo: `flood-report.sh --unmitigate` removes the table.
#
# SAFETY (the same rules as security-report.sh):
#   - A check that CANNOT READ its signal publishes NOTHING for it (never a false
#     "0 / all-clear", never a false "resolved" that would clear a real open alert);
#     all unreadable checks fold into ONE `monitor-unreadable-flood` card.
#   - A check whose signal does not EXIST on this box (no Caddy, no mailserver) is
#     inert; it returns early and posts nothing (not "unreadable"). A `docker ps` or
#     `docker logs` that fails, or an `ss` that fails, is unreadable: it cannot tell
#     "nothing there" from "could not look".
#   - Transition-only, per-event state under $HOSTSEC_FLOOD_STATE_DIR; a standing
#     condition is raised once and re-asserted at most every HOSTSEC_FLOOD_RESURFACE_SECS.
#   - Rate checks BASELINE on the first run (no window yet) and never alert on history.
#   - Only a 2xx counts as sent: a report that was not delivered changes no state and
#     goes again on the next run (over the per-run cap too). After one post gets no
#     answer at all, the rest of the run's posts wait for the next run.
#   - Per-run post cap; kill switch; the script NEVER exits non-zero. Read-only on the
#     system EXCEPT the DARK-by-default, self-expiring, reversible nft mitigation.
#
# Env (all optional except the report transport's). Thresholds ship HIGH so a busy
# box never cries wolf; baseline each box, then ratchet down. Keep your tuned values in
# the mode-600 /etc/nethersec/flood.env; they tell an attacker how far under the radar
# to stay, so never publish them.
#   NETHERSEC_REPORT_URL / NETHERSEC_REPORT_KEY / NETHERSEC_REPORT_FORMAT  passed through
#                             to nethersec-report.sh (see its header)
#   HOSTSEC_FLOOD_SOURCE      box name for --source (default: HOSTSEC_SOURCE or `hostname -s`)
#   HOSTSEC_FLOOD_GROUP       optional grouping label for --group (default: HOSTSEC_GROUP)
#   HOSTSEC_FLOOD_REPORT_SCRIPT path to nethersec-report.sh (default: sibling nethersec-report.sh)
#   HOSTSEC_FLOOD_STATE_DIR   transition-state dir (default: /var/lib/nethersec)
#   HOSTSEC_FLOOD_RESURFACE_SECS  re-assert a still-raised condition at most this often (default 3600)
#   HOSTSEC_FLOOD_MAX_POSTS   per-run post cap (default 6)
#   HOSTSEC_FLOOD_KILL_FILE / HOSTSEC_FLOOD_KILL  flood-only kill switch (default /etc/nethersec/flood-disabled)
#                             (the shared /etc/nethersec/disabled pauses this too)
#   check 1 (connection):
#     HOSTSEC_FLOOD_CONNTRACK_PCT  conntrack count/max % that raises (default 85; 0=off)
#     HOSTSEC_FLOOD_SYNRECV        SYN-recv half-open count that raises (default 500; 0=off)
#     HOSTSEC_FLOOD_ESTAB_MIN      established conns before a dominant-source check (default 3000; 0=off)
#     HOSTSEC_FLOOD_ESTAB_SHARE_PCT top-source share % of established that raises (default 60)
#     HOSTSEC_FLOOD_CONN_SEVERITY  critical|warning(default)|info
#   check 2 (network volume):
#     HOSTSEC_FLOOD_PPS            inbound packets/sec that raises (default 120000; 0=off)
#     HOSTSEC_FLOOD_MBPS           inbound megabits/sec that raises (default 800; 0=off)
#     HOSTSEC_FLOOD_NET_IFACE      interface to watch (default: the default-route iface)
#     HOSTSEC_FLOOD_NET_SEVERITY   critical|warning(default)|info
#   check 3 (HTTP):
#     HOSTSEC_FLOOD_HTTP_ENABLE    1 (default) | 0
#     HOSTSEC_FLOOD_HTTP_CONTAINER caddy container name (default: auto-detect a *caddy* container)
#     HOSTSEC_FLOOD_HTTP_MIN       requests in the window before a dominant-source check (default 6000; 0=off)
#     HOSTSEC_FLOOD_HTTP_SHARE_PCT top-client share % that raises and names (and can block) it (default 55)
#     HOSTSEC_FLOOD_HTTP_TOTAL_PER_MIN  requests a minute from all clients together that raise
#                                  with no single source over the share; never blocks (default 18000; 0=off)
#     HOSTSEC_FLOOD_HTTP_SEVERITY  critical|warning(default)|info
#     HOSTSEC_FLOOD_HTTP_AGG       path to flood-http-aggregate.py (default: sibling)
#   check 4 (SMTP):
#     HOSTSEC_FLOOD_SMTP_ENABLE    1 (default) | 0
#     HOSTSEC_FLOOD_SMTP_CONTAINER mailserver container (default: auto-detect *mail*)
#     HOSTSEC_FLOOD_SMTP_MIN       `connect from` events in the window that raises (default 1500; 0=off)
#     HOSTSEC_FLOOD_SMTP_SHARE_PCT share % at which the card names the top source (default 60)
#     HOSTSEC_FLOOD_SMTP_SEVERITY  critical|warning(default)|info
#   mitigation (DARK):
#     HOSTSEC_FLOOD_MITIGATE       1 to arm the real nft drop; 0 (default) = dry-run/log only.
#                                  Only the exact value 1 arms it; anything else is 0, logged
#     HOSTSEC_FLOOD_MITIGATE_MINUTES  self-expiry of an auto-drop (default 60)
#     HOSTSEC_FLOOD_MITIGATE_MAX_PER_HOUR  cap on auto-drops per hour (default 6)
#     HOSTSEC_FLOOD_ALLOW_IPS      comma/space list of IPs to NEVER drop (your app's egress, monitors)
#
# Exit: always 0. Optional maintenance verbs (run by hand): `--unmitigate` removes the
# whole nft mitigation table; `--unmitigate-ip <ip>` removes one dropped IP.
set -u

log() { echo "flood-report: $*" >&2; }

# --- config ------------------------------------------------------------------
STATE_DIR="${HOSTSEC_FLOOD_STATE_DIR:-/var/lib/nethersec}"
SOURCE="${HOSTSEC_FLOOD_SOURCE:-${HOSTSEC_SOURCE:-$( (hostname -s 2>/dev/null || hostname 2>/dev/null || echo box) | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' | cut -c 1-40)}}"
GROUP="${HOSTSEC_FLOOD_GROUP:-${HOSTSEC_GROUP:-}}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P 2>/dev/null || echo .)
REPORT="${HOSTSEC_FLOOD_REPORT_SCRIPT:-$SCRIPT_DIR/nethersec-report.sh}"
AGG_HTTP="${HOSTSEC_FLOOD_HTTP_AGG:-$SCRIPT_DIR/flood-http-aggregate.py}"
RESURFACE="${HOSTSEC_FLOOD_RESURFACE_SECS:-3600}"
MAX_POSTS="${HOSTSEC_FLOOD_MAX_POSTS:-6}"

CONNTRACK_PCT="${HOSTSEC_FLOOD_CONNTRACK_PCT:-85}"
SYNRECV="${HOSTSEC_FLOOD_SYNRECV:-500}"
ESTAB_MIN="${HOSTSEC_FLOOD_ESTAB_MIN:-3000}"
ESTAB_SHARE_PCT="${HOSTSEC_FLOOD_ESTAB_SHARE_PCT:-60}"
CONN_SEVERITY="${HOSTSEC_FLOOD_CONN_SEVERITY:-warning}"
case "$CONN_SEVERITY" in critical|warning|info) ;; *) CONN_SEVERITY="warning" ;; esac

PPS="${HOSTSEC_FLOOD_PPS:-120000}"
MBPS="${HOSTSEC_FLOOD_MBPS:-800}"
NET_IFACE="${HOSTSEC_FLOOD_NET_IFACE:-}"
NET_SEVERITY="${HOSTSEC_FLOOD_NET_SEVERITY:-warning}"
case "$NET_SEVERITY" in critical|warning|info) ;; *) NET_SEVERITY="warning" ;; esac

HTTP_ENABLE="${HOSTSEC_FLOOD_HTTP_ENABLE:-1}"
HTTP_CONTAINER="${HOSTSEC_FLOOD_HTTP_CONTAINER:-}"
HTTP_MIN="${HOSTSEC_FLOOD_HTTP_MIN:-6000}"
HTTP_SHARE_PCT="${HOSTSEC_FLOOD_HTTP_SHARE_PCT:-55}"
HTTP_TOTAL_PER_MIN="${HOSTSEC_FLOOD_HTTP_TOTAL_PER_MIN:-18000}"
case "$HTTP_TOTAL_PER_MIN" in ''|*[!0-9]*) HTTP_TOTAL_PER_MIN=18000 ;; esac
HTTP_SEVERITY="${HOSTSEC_FLOOD_HTTP_SEVERITY:-warning}"
case "$HTTP_SEVERITY" in critical|warning|info) ;; *) HTTP_SEVERITY="warning" ;; esac

SMTP_ENABLE="${HOSTSEC_FLOOD_SMTP_ENABLE:-1}"
SMTP_CONTAINER="${HOSTSEC_FLOOD_SMTP_CONTAINER:-}"
SMTP_MIN="${HOSTSEC_FLOOD_SMTP_MIN:-1500}"
SMTP_SHARE_PCT="${HOSTSEC_FLOOD_SMTP_SHARE_PCT:-60}"
SMTP_SEVERITY="${HOSTSEC_FLOOD_SMTP_SEVERITY:-warning}"
case "$SMTP_SEVERITY" in critical|warning|info) ;; *) SMTP_SEVERITY="warning" ;; esac

MITIGATE="${HOSTSEC_FLOOD_MITIGATE-0}"   # only exactly 1 arms it (checked after the kill switch)
MIT_MINUTES="${HOSTSEC_FLOOD_MITIGATE_MINUTES:-60}"
case "$MIT_MINUTES" in ''|*[!0-9]*) MIT_MINUTES=60 ;; esac
MIT_MAX_PER_HOUR="${HOSTSEC_FLOOD_MITIGATE_MAX_PER_HOUR:-6}"
case "$MIT_MAX_PER_HOUR" in ''|*[!0-9]*) MIT_MAX_PER_HOUR=6 ;; esac
ALLOW_IPS="${HOSTSEC_FLOOD_ALLOW_IPS:-}"

# Seams for the offline test harness (so it needs no real /proc, ss, docker or nft):
NFT_CMD="${HOSTSEC_FLOOD_NFT_CMD:-nft}"
DOCKER_CMD="${HOSTSEC_FLOOD_DOCKER_CMD:-docker}"
SS_CMD="${HOSTSEC_FLOOD_SS_CMD:-ss}"
IP_CMD="${HOSTSEC_FLOOD_IP_CMD:-ip}"
NETDEV_FILE="${HOSTSEC_FLOOD_NETDEV_FILE:-/proc/net/dev}"
CONNTRACK_COUNT_FILE="${HOSTSEC_FLOOD_CONNTRACK_COUNT_FILE:-}"
CONNTRACK_MAX_FILE="${HOSTSEC_FLOOD_CONNTRACK_MAX_FILE:-}"
# Command that reads Caddy JSON log lines on stdin and prints the aggregate line.
# Empty => built from python3 + flood-http-aggregate.py at check time (or unreadable).
HTTP_AGG_CMD="${HOSTSEC_FLOOD_HTTP_AGG_CMD:-}"

# --- protected CDN / good-bot ranges -----------------------------------------
# IPv4 CIDRs (Cloudflare's published ranges + a Fastly subset) and IPv6 textual
# prefixes. A dominant source inside one of these is a CDN that fronts good bots and
# perhaps your own site; never
# mitigate it (over-refusing is the safe failure). The HTTP aggregator applies the
# same list (its traffic still counts, the source is only marked exempt from a block);
# this sh copy guards the conn-flood dominant IP and the mitigation.
PROTECTED_CIDRS="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 23.235.32.0/20 43.249.72.0/22 103.244.50.0/24 103.245.222.0/23 103.245.224.0/24 104.156.80.0/20 140.248.64.0/18 140.248.128.0/17 146.75.0.0/17 151.101.0.0/16 157.52.64.0/18 167.82.0.0/17 185.31.16.0/22 199.27.72.0/21"
PROTECTED_V6_PREFIXES="2400:cb00: 2606:4700: 2803:f800: 2405:b500: 2405:8100: 2a06:98c0: 2c0f:f248: 2a04:4e40: 2a04:4e42:"

# --- optional maintenance verbs ----------------------------------------------
case "${1:-}" in
  --unmitigate)
    if "$NFT_CMD" delete table inet nethersec_flood >/dev/null 2>&1; then
      log "removed the nftables mitigation table (all flood drops cleared)."
    else
      log "no nftables mitigation table to remove (or nft unavailable)."
    fi
    exit 0 ;;
  --unmitigate-ip)
    mi="${2:-}"
    [ -n "$mi" ] || { log "--unmitigate-ip needs an IP"; exit 0; }
    if "$NFT_CMD" delete element inet nethersec_flood flood_drop "{ $mi }" >/dev/null 2>&1; then
      log "removed $mi from the nftables flood-drop set."
    else
      log "could not remove $mi (not present, or nft unavailable)."
    fi
    exit 0 ;;
  '' ) : ;;   # normal run
  * ) log "unknown arg '${1:-}' (use no args for a normal run, or --unmitigate[ -ip <ip>])" ;;
esac

# --- kill switch -------------------------------------------------------------
KILL_FILE="${HOSTSEC_FLOOD_KILL_FILE:-/etc/nethersec/flood-disabled}"
if [ "${HOSTSEC_FLOOD_KILL:-0}" = "1" ] || [ -f "$KILL_FILE" ] || [ -f /etc/nethersec/disabled ]; then
  log "disabled (kill switch); exiting 0"
  exit 0
fi

# The transport needs a URL, and a key unless the format works without one (Discord,
# ntfy, json). Without them nothing can be posted, so fail SAFE (log + exit 0) rather
# than record a state change nobody was told about.
report_ready() {
  [ -n "${NETHERSEC_REPORT_URL:-}" ] || return 1
  [ -n "${NETHERSEC_REPORT_KEY:-}" ] && return 0
  case "${NETHERSEC_REPORT_FORMAT:-}" in discord|ntfy|json) return 0 ;; '') ;; *) return 1 ;; esac
  case "$NETHERSEC_REPORT_URL" in
    https://discord.com/api/webhooks/*|https://*.discord.com/api/webhooks/*|https://discordapp.com/api/webhooks/*|https://*.discordapp.com/api/webhooks/*) return 0 ;;
  esac
  return 1
}
if ! report_ready; then
  log "NETHERSEC_REPORT_URL (or the hub format's NETHERSEC_REPORT_KEY) unset; nothing to post to. Exiting 0."
  exit 0
fi
if [ ! -x "$REPORT" ] && [ ! -f "$REPORT" ]; then
  log "report transport not found at $REPORT; exiting 0"
  exit 0
fi
if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
  log "cannot create state dir $STATE_DIR; exiting 0"
  exit 0
fi

# The switch that arms the drops fails safe: only the exact value 1 blocks. Anything else
# (empty, "true", "yes", a typo) leaves blocking off and says so.
case "$MITIGATE" in
  0|1) : ;;
  *) log "HOSTSEC_FLOOD_MITIGATE='$MITIGATE' is not 0 or 1; blocking stays off (only 1 arms it)"; MITIGATE=0 ;;
esac

NOW="${HOSTSEC_FLOOD_NOW:-$(date +%s 2>/dev/null || echo 0)}"
case "$NOW" in ''|*[!0-9]*) NOW=0 ;; esac
# Shared window clock for the rate checks (net/http/smtp): 0 on the first run.
LAST=0
if [ -f "$STATE_DIR/flood-lastrun" ]; then
  read -r LAST < "$STATE_DIR/flood-lastrun" 2>/dev/null || LAST=0
  case "$LAST" in ''|*[!0-9]*) LAST=0 ;; esac
fi
WIN=$((NOW - LAST)); [ "$WIN" -lt 1 ] && WIN=1
POSTS=0
OVERFLOW=0
# Set once a post got no answer at all (nethersec-report.sh exit 3). The rest of this
# run's posts wait for the next run, so a hub that is down costs one timeout a run and
# the run stays inside its unit's time limit.
HUB_DOWN=0
DEFERRED=0

# --- post helper (per-run cap; never aborts on transport error) --------------
# EMIT_OK is 1 only when this post was delivered (a 2xx).
EMIT_OK=0
emit() {
  EMIT_OK=0
  if [ "$POSTS" -ge "$MAX_POSTS" ]; then OVERFLOW=$((OVERFLOW + 1)); return 0; fi
  if [ "$HUB_DOWN" = 1 ]; then DEFERRED=$((DEFERRED + 1)); return 0; fi
  POSTS=$((POSTS + 1))
  if [ -n "$GROUP" ]; then
    sh "$REPORT" --kind security --source "$SOURCE" --group "$GROUP" "$@" >/dev/null 2>&1
  else
    sh "$REPORT" --kind security --source "$SOURCE" "$@" >/dev/null 2>&1
  fi
  em_rc=$?
  if [ "$em_rc" -eq 0 ]; then
    EMIT_OK=1
  else
    [ "$em_rc" -eq 3 ] && HUB_DOWN=1
    log "post failed (source=$SOURCE): $*"
  fi
}

# --- transition engine (raise once, resolve once, throttled re-surface) ------
# The state file says what the hub was last told, so it changes only after a 2xx: a
# raise that failed or was over the cap goes again on the next run, and a resolve that
# failed keeps the file so it goes again too.
transition() {
  te_ev="$1"; te_cur="$2"; te_sev="$3"; te_title="$4"; te_detail="$5"
  te_f="$STATE_DIR/flood-ev.$te_ev"
  if [ "$te_cur" = "raised" ]; then
    if [ -f "$te_f" ]; then
      te_ssev=""; te_sasrt=0
      read -r te_ssev te_sasrt < "$te_f" 2>/dev/null || { te_ssev=""; te_sasrt=0; }
      case "$te_sasrt" in ''|*[!0-9]*) te_sasrt=0 ;; esac
      if [ "$te_ssev" = "$te_sev" ] && [ $((NOW - te_sasrt)) -lt "$RESURFACE" ]; then
        return 0
      fi
    fi
    emit --event "$te_ev" --state triggered --severity "$te_sev" --title "$te_title" --detail "$te_detail"
    [ "$EMIT_OK" = "1" ] || return 0
    printf '%s %s\n' "$te_sev" "$NOW" > "$te_f" 2>/dev/null || log "state write failed: $te_f"
  else
    if [ -f "$te_f" ]; then
      emit --event "$te_ev" --state resolved --title "$te_title"
      [ "$EMIT_OK" = "1" ] || return 0
      rm -f "$te_f" 2>/dev/null || log "state clear failed: $te_f"
    fi
  fi
}

# --- helpers -----------------------------------------------------------------
# ip -> uint32 (echo empty on a non-IPv4).
_ip_to_int() {
  case "$1" in
    *.*.*.*) : ;; *) return 1 ;;
  esac
  IFS=. read -r a b c d <<EOF
$1
EOF
  case "$a$b$c$d" in *[!0-9]*) return 1 ;; esac
  [ "$a" -le 255 ] 2>/dev/null && [ "$b" -le 255 ] 2>/dev/null && [ "$c" -le 255 ] 2>/dev/null && [ "$d" -le 255 ] 2>/dev/null || return 1
  echo $(( (a * 16777216) + (b * 65536) + (c * 256) + d ))
}
# is $1 inside a "base/len" CIDR?
_in_cidr() {
  ic_ip="$1"; ic_cidr="$2"
  ic_base=${ic_cidr%/*}; ic_len=${ic_cidr#*/}
  case "$ic_len" in ''|*[!0-9]*) return 1 ;; esac
  ic_ai=$(_ip_to_int "$ic_ip") || return 1
  ic_bi=$(_ip_to_int "$ic_base") || return 1
  [ "$ic_len" -eq 0 ] && return 0
  [ "$ic_len" -gt 32 ] && return 1
  # Compare the top `len` bits: dividing by 2^(32-len) drops the low (host) bits,
  # so equal quotients == same network (equivalent to masking, no overflow).
  ic_shift=$((32 - ic_len))
  [ $(( ic_ai / (1 << ic_shift) )) -eq $(( ic_bi / (1 << ic_shift) )) ]
}
# is $1 a protected CDN / good-bot address (never mitigate)?
is_protected_ip() {
  ip_p="$1"
  case "$ip_p" in
    *:*)
      for pfx in $PROTECTED_V6_PREFIXES; do
        case "$ip_p" in "$pfx"*) return 0 ;; esac
      done
      return 1 ;;
  esac
  for c in $PROTECTED_CIDRS; do
    _in_cidr "$ip_p" "$c" && return 0
  done
  return 1
}
# is $1 on the never-drop allow-list?
# Addresses a drop must never hit, because they are not a remote attacker: loopback,
# private and carrier-grade NAT ranges, link-local, multicast and reserved space (a proxy
# or tunnel in front of the site, or an app talking to a local database, shows up as one
# of these), plus the box's own addresses and its default gateway. Dropping one of them
# would cut the box off from itself. When `ip` is installed but cannot be read, every
# address counts as possibly the box's own and nothing is dropped.
NEVER_DROP_CIDRS="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
_is_local_ip() {
  for c in $NEVER_DROP_CIDRS; do
    _in_cidr "$1" "$c" && return 0
  done
  command -v "$IP_CMD" >/dev/null 2>&1 || return 1
  il_own=$("$IP_CMD" -4 -o addr show 2>/dev/null) || return 0
  printf '%s\n' "$il_own" | awk '{ for (i = 1; i < NF; i++) if ($i == "inet") { sub(/\/.*/, "", $(i + 1)); print $(i + 1) } }' \
    | grep -qxF "$1" && return 0
  il_gw=$("$IP_CMD" -4 route show default 2>/dev/null) || return 0
  printf '%s\n' "$il_gw" | awk '{ for (i = 1; i < NF; i++) if ($i == "via") print $(i + 1) }' | grep -qxF "$1" && return 0
  return 1
}
_in_allowlist() {
  ia_ip="$1"
  for a in $(printf '%s' "$ALLOW_IPS" | tr ',' ' '); do
    [ "$a" = "$ia_ip" ] && return 0
  done
  return 1
}
# stdin: one IP per line -> "<total> <topcount> <topip>" (topip '-' when empty).
_dominant() {
  awk 'NF{c[$0]++; n++} END{
    top=0; ti="-";
    for(k in c){ if(c[k]>top){top=c[k]; ti=k} }
    printf "%d %d %s\n", n, top, ti }'
}

# --- DARK-by-default nftables mitigation -------------------------------------
MIT_NOTE=""
_under_mitigate_cap() {
  # fail-OPEN: a state hiccup must never stop a live mitigation.
  umc_bucket=$((NOW / 3600))
  umc_f="$STATE_DIR/flood-mit.$umc_bucket"
  umc_n=0
  [ -f "$umc_f" ] && { read -r umc_n < "$umc_f" 2>/dev/null || umc_n=0; }
  case "$umc_n" in ''|*[!0-9]*) umc_n=0 ;; esac
  [ "$umc_n" -lt "$MIT_MAX_PER_HOUR" ]
}
_bump_mitigate_cap() {
  bmc_bucket=$((NOW / 3600))
  bmc_f="$STATE_DIR/flood-mit.$bmc_bucket"
  bmc_n=0
  [ -f "$bmc_f" ] && { read -r bmc_n < "$bmc_f" 2>/dev/null || bmc_n=0; }
  case "$bmc_n" in ''|*[!0-9]*) bmc_n=0 ;; esac
  printf '%s\n' "$((bmc_n + 1))" > "$bmc_f" 2>/dev/null || :
}
_apply_drop() {
  ad_ip="$1"; ad_min="$2"
  # Defence in depth before touching nft: a single bare IPv4 and an explicit,
  # positive-integer timeout ONLY. A comma/space list in $ad_ip would leave the
  # earlier elements without the trailing `timeout` (added as NON-expiring drops); an
  # empty/garbage $ad_min would do the same.
  case "$ad_ip" in ''|*[!0-9.]*) return 1 ;; esac
  case "$ad_min" in ''|*[!0-9]*) ad_min=60 ;; esac
  [ "$ad_min" -ge 1 ] 2>/dev/null || ad_min=60
  command -v "$NFT_CMD" >/dev/null 2>&1 || return 1
  if ! "$NFT_CMD" list table inet nethersec_flood >/dev/null 2>&1; then
    "$NFT_CMD" -f - >/dev/null 2>&1 <<'NFT' || return 1
table inet nethersec_flood {
	set flood_drop {
		type ipv4_addr
		flags timeout
	}
	chain pre {
		type filter hook prerouting priority -300; policy accept;
		ip saddr @flood_drop drop
	}
}
NFT
  fi
  "$NFT_CMD" add element inet nethersec_flood flood_drop "{ $ad_ip timeout ${ad_min}m }" >/dev/null 2>&1
}
# mitigate one confirmed dominant IPv4; sets MIT_NOTE for the alert detail. Every
# decline falls through to the alert (worst case: alerted, not blocked).
mitigate_ip() {
  MIT_NOTE=""
  mi_ip="$1"
  case "$mi_ip" in ''|-) return ;; *:*) MIT_NOTE=" [mitigation n/a: $mi_ip is IPv6]"; return ;; esac
  # Strict dotted-quad guard BEFORE any nft call. _ip_to_int enforces exactly four
  # octets each 0-255 and nothing else, so a spoofed/garbage value (a comma-list, a
  # space, an injection) can never reach the nft set; a comma-list would otherwise
  # add its earlier elements with NO timeout (a non-expiring drop).
  if ! _ip_to_int "$mi_ip" >/dev/null 2>&1; then
    MIT_NOTE=" [mitigation skipped: $mi_ip is not a valid IPv4]"
    return
  fi
  if _is_local_ip "$mi_ip"; then MIT_NOTE=" [mitigation skipped: $mi_ip is a local, private or own address]"; return; fi
  if is_protected_ip "$mi_ip"; then MIT_NOTE=" [mitigation skipped: $mi_ip is a protected CDN/good-bot range]"; return; fi
  if _in_allowlist "$mi_ip"; then MIT_NOTE=" [mitigation skipped: $mi_ip is allow-listed]"; return; fi
  if [ "$MITIGATE" != "1" ]; then
    MIT_NOTE=" [would drop $mi_ip for ${MIT_MINUTES}m; mitigation DARK/dry-run]"
    log "DRY-RUN: would nft-drop $mi_ip for ${MIT_MINUTES}m (HOSTSEC_FLOOD_MITIGATE=0)"
    return
  fi
  if ! _under_mitigate_cap; then
    MIT_NOTE=" [mitigation cap reached this hour; $mi_ip alerted, not blocked]"
    return
  fi
  if _apply_drop "$mi_ip" "$MIT_MINUTES"; then
    _bump_mitigate_cap
    MIT_NOTE=" [auto-dropped $mi_ip for ${MIT_MINUTES}m; self-expiring nft rule; undo: flood-report.sh --unmitigate]"
    log "mitigated: nft-dropped $mi_ip for ${MIT_MINUTES}m"
  else
    MIT_NOTE=" [mitigation FAILED for $mi_ip (no nft / not root?); alerted, not blocked]"
  fi
}

# Checks set these, then the runner acts.
R_STATE="ok"; R_SEV="warning"; R_DETAIL=""
UNREADABLE=""

# --- check 1: connection flood (conntrack / SYN-recv / dominant established) --
check_conn_flood() {
  R_STATE="ok"; R_SEV="$CONN_SEVERITY"; R_DETAIL=""
  cf_read=0            # 1 once any leg was readable
  cf_parts=""          # detail fragments for whatever tripped
  cf_dom_ip="-"        # a confirmed dominant source, for mitigation

  # (a) conntrack table saturation.
  if [ "${CONNTRACK_PCT:-0}" != "0" ]; then
    cf_cnt=""; cf_max=""
    for p in ${CONNTRACK_COUNT_FILE:-} /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/nf_conntrack_count; do
      [ -n "$p" ] && [ -r "$p" ] && { read -r cf_cnt < "$p" 2>/dev/null || cf_cnt=""; break; }
    done
    for p in ${CONNTRACK_MAX_FILE:-} /proc/sys/net/netfilter/nf_conntrack_max /proc/sys/net/nf_conntrack_max; do
      [ -n "$p" ] && [ -r "$p" ] && { read -r cf_max < "$p" 2>/dev/null || cf_max=""; break; }
    done
    case "$cf_cnt" in ''|*[!0-9]*) cf_cnt="" ;; esac
    case "$cf_max" in ''|*[!0-9]*) cf_max="" ;; esac
    if [ -n "$cf_cnt" ] && [ -n "$cf_max" ] && [ "$cf_max" -gt 0 ]; then
      cf_read=1
      cf_pct=$(( cf_cnt * 100 / cf_max ))
      if [ "$cf_pct" -ge "$CONNTRACK_PCT" ]; then
        cf_parts="${cf_parts}conntrack ${cf_cnt}/${cf_max} (${cf_pct}%); "
      fi
    fi
  fi

  # (b) SYN-recv half-open burst (a SYN flood) + (c) dominant established source.
  # A pipeline's status is only its last command's, so ss's own exit status comes back on
  # fd 3 ("rc-ss N"): an ss that failed must never read as zero sockets. An ss that is
  # installed but fails makes the check unreadable unless another leg already shows a
  # flood, so a card it raised is never resolved on the conntrack leg alone.
  cf_ssfail=0
  if command -v "$SS_CMD" >/dev/null 2>&1; then
    cf_res=$( { { "$SS_CMD" -tanH state syn-recv 2>/dev/null; echo "rc-ss $?" >&3; } | grep -c .; } 3>&1 )
    cf_rc=$(printf '%s\n' "$cf_res" | sed -n 's/^rc-ss //p')
    cf_syn=$(printf '%s\n' "$cf_res" | grep -v '^rc-ss ' | head -n 1)
    case "$cf_syn" in ''|*[!0-9]*) cf_syn="" ;; esac
    if [ "$cf_rc" = 0 ] && [ -n "$cf_syn" ]; then
      cf_read=1
      if [ "${SYNRECV:-0}" != "0" ] && [ "$cf_syn" -ge "$SYNRECV" ]; then
        cf_parts="${cf_parts}syn-recv=${cf_syn} (half-open/SYN flood); "
      fi
    else
      cf_ssfail=1
    fi
    if [ "${ESTAB_MIN:-0}" != "0" ]; then
      # Peer address is the last field; strip the :port (and [] for IPv6).
      cf_res=$( { { "$SS_CMD" -tanH state established 2>/dev/null; echo "rc-ss $?" >&3; } \
        | awk '{print $NF}' | sed -e 's/\]:[0-9]*$//' -e 's/^\[//' -e 's/:[0-9]*$//' \
        | awk 'NF' | _dominant; } 3>&1 )
      cf_rc=$(printf '%s\n' "$cf_res" | sed -n 's/^rc-ss //p')
      cf_dom=$(printf '%s\n' "$cf_res" | grep -v '^rc-ss ' | head -n 1)
      [ "$cf_rc" = 0 ] || { cf_dom=""; cf_ssfail=1; }
      if [ -n "$cf_dom" ]; then
        cf_read=1
        cf_total=$(printf '%s' "$cf_dom" | awk '{print $1}')
        cf_top=$(printf '%s' "$cf_dom" | awk '{print $2}')
        cf_ip=$(printf '%s' "$cf_dom" | awk '{print $3}')
        case "$cf_total" in ''|*[!0-9]*) cf_total=0 ;; esac
        case "$cf_top" in ''|*[!0-9]*) cf_top=0 ;; esac
        if [ "$cf_total" -ge "$ESTAB_MIN" ] && [ "$cf_total" -gt 0 ]; then
          cf_share=$(( cf_top * 100 / cf_total ))
          # A dominant peer that is a protected CDN range is EXPECTED fronting (on an
          # box behind Cloudflare every established peer is Cloudflare); not an attack, and
          # never something to mitigate. Only a non-CDN source counts as a flood.
          if [ "$cf_share" -ge "$ESTAB_SHARE_PCT" ] && [ "$cf_ip" != "-" ] && ! is_protected_ip "$cf_ip"; then
            cf_parts="${cf_parts}${cf_ip} holds ${cf_top}/${cf_total} established (${cf_share}%); "
            cf_dom_ip="$cf_ip"
          fi
        fi
      fi
    fi
  fi

  if [ -n "$cf_parts" ]; then
    mitigate_ip "$cf_dom_ip"
    R_STATE="raised"
    R_DETAIL="connection flood: ${cf_parts}${MIT_NOTE}"
    return
  fi
  if [ "$cf_read" -eq 0 ] || [ "$cf_ssfail" -eq 1 ]; then R_STATE="unreadable"; fi
}

# --- check 2: inbound network volume (PPS / BPS from /proc/net/dev) -----------
check_net_volume() {
  R_STATE="ok"; R_SEV="$NET_SEVERITY"; R_DETAIL=""
  [ "${PPS:-0}" != "0" ] || [ "${MBPS:-0}" != "0" ] || return
  [ -r "$NETDEV_FILE" ] || { R_STATE="unreadable"; return; }
  nv_if="$NET_IFACE"
  if [ -z "$nv_if" ]; then
    nv_if=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [ -n "$nv_if" ] || nv_if="eth0"
  fi
  # /proc/net/dev columns after "iface:": 1=rxbytes 2=rxpackets ... 9=txbytes 10=txpackets
  nv_line=$(grep -E "^[[:space:]]*${nv_if}:" "$NETDEV_FILE" 2>/dev/null | sed 's/.*://')
  [ -n "$nv_line" ] || { R_STATE="unreadable"; return; }
  nv_rxb=$(printf '%s' "$nv_line" | awk '{print $1}')
  nv_rxp=$(printf '%s' "$nv_line" | awk '{print $2}')
  case "$nv_rxb" in ''|*[!0-9]*) R_STATE="unreadable"; return ;; esac
  case "$nv_rxp" in ''|*[!0-9]*) R_STATE="unreadable"; return ;; esac

  nv_state="$STATE_DIR/flood-netdev"
  nv_pe=0; nv_pif=""; nv_prxb=0; nv_prxp=0
  if [ -f "$nv_state" ]; then
    read -r nv_pe nv_pif nv_prxb nv_prxp < "$nv_state" 2>/dev/null || nv_pe=0
    case "$nv_pe" in ''|*[!0-9]*) nv_pe=0 ;; esac
    case "$nv_prxb" in ''|*[!0-9]*) nv_prxb=0 ;; esac
    case "$nv_prxp" in ''|*[!0-9]*) nv_prxp=0 ;; esac
  fi
  # Always store the fresh sample for next time.
  printf '%s %s %s %s\n' "$NOW" "$nv_if" "$nv_rxb" "$nv_rxp" > "$nv_state" 2>/dev/null || :

  # First sample, an iface change, a counter wrap, or a zero window -> baseline only.
  [ "$nv_pe" -gt 0 ] || return
  [ "$nv_pif" = "$nv_if" ] || return
  [ "$nv_rxb" -ge "$nv_prxb" ] || return
  [ "$nv_rxp" -ge "$nv_prxp" ] || return
  nv_win=$((NOW - nv_pe)); [ "$nv_win" -lt 1 ] && return

  nv_pps=$(( (nv_rxp - nv_prxp) / nv_win ))
  nv_mbps=$(( (nv_rxb - nv_prxb) * 8 / (nv_win * 1000000) ))
  nv_parts=""
  if [ "${PPS:-0}" != "0" ] && [ "$nv_pps" -ge "$PPS" ]; then nv_parts="${nv_parts}${nv_pps} pkts/s; "; fi
  if [ "${MBPS:-0}" != "0" ] && [ "$nv_mbps" -ge "$MBPS" ]; then nv_parts="${nv_parts}${nv_mbps} Mbit/s; "; fi
  if [ -n "$nv_parts" ]; then
    R_STATE="raised"
    R_DETAIL="inbound volume on ${nv_if}: ${nv_parts}(no single source; volumetric; mitigate upstream)"
  fi
}

# --- check 3: HTTP request flood (Caddy JSON access log) ----------------------
check_http_flood() {
  R_STATE="ok"; R_SEV="$HTTP_SEVERITY"; R_DETAIL=""
  [ "$HTTP_ENABLE" = "1" ] || return
  command -v "$DOCKER_CMD" >/dev/null 2>&1 || return   # no docker -> not applicable here
  hf_cid="$HTTP_CONTAINER"
  if [ -z "$hf_cid" ]; then
    # A `docker ps` that fails cannot tell "no Caddy here" from "Caddy we cannot see".
    if ! hf_ps=$("$DOCKER_CMD" ps --format '{{.Names}}' 2>/dev/null); then R_STATE="unreadable"; return; fi
    hf_cid=$(printf '%s\n' "$hf_ps" | grep -iE 'caddy' | head -1)
  fi
  [ -n "$hf_cid" ] || return       # no Caddy container -> inert (not unreadable)
  [ "$LAST" -gt 0 ] || return      # first run -> baseline only
  # Resolve the aggregator command (a test seam can inject a mock). Default =
  # python3 + flood-http-aggregate.py; if python3 or the helper is missing the check
  # is unreadable (never a fabricated all-clear).
  hf_agg="$HTTP_AGG_CMD"
  if [ -z "$hf_agg" ]; then
    if command -v python3 >/dev/null 2>&1 && [ -f "$AGG_HTTP" ]; then
      hf_agg="python3 -I $AGG_HTTP"
    else
      R_STATE="unreadable"; return
    fi
  fi
  # A pipeline's status is only its last command's, and the aggregator prints a quiet
  # "0 0 - 0 0 0" for no input, so a `docker logs` that failed would read as a quiet window
  # and could close an open card. Both exit statuses come back on fd 3 instead.
  # shellcheck disable=SC2086  # hf_agg is a command + arg ("python3 <path>"), intentional split
  hf_res=$( { { "$DOCKER_CMD" logs --since "$LAST" "$hf_cid" 2>/dev/null; echo "rc-docker $?" >&3; } \
    | $hf_agg 2>/dev/null; echo "rc-agg $?" >&3; } 3>&1 )
  hf_drc=$(printf '%s\n' "$hf_res" | sed -n 's/^rc-docker //p')
  hf_arc=$(printf '%s\n' "$hf_res" | sed -n 's/^rc-agg //p')
  hf_out=$(printf '%s\n' "$hf_res" | grep -v '^rc-' | awk 'NF' | tail -n 1)
  if [ "$hf_drc" != 0 ] || [ "$hf_arc" != 0 ]; then R_STATE="unreadable"; return; fi
  # aggregator prints: "<total> <topcount> <topip> <sharepct> <lines_seen> <topexempt>";
  # anything else (nothing, or a garbled line) is unreadable, never a zero.
  printf '%s\n' "$hf_out" | grep -Eq '^[0-9]+ [0-9]+ [^ ]+ [0-9]+ [0-9]+ [01]$' || { R_STATE="unreadable"; return; }
  hf_total=$(printf '%s' "$hf_out" | awk '{print $1}')
  hf_top=$(printf '%s' "$hf_out" | awk '{print $2}')
  hf_ip=$(printf '%s' "$hf_out" | awk '{print $3}')
  hf_share=$(printf '%s' "$hf_out" | awk '{print $4}')
  hf_lines=$(printf '%s' "$hf_out" | awk '{print $5}')
  hf_exempt=$(printf '%s' "$hf_out" | awk '{print $6}')
  case "$hf_total" in ''|*[!0-9]*) hf_total=0 ;; esac
  case "$hf_lines" in ''|*[!0-9]*) hf_lines=0 ;; esac
  case "$hf_share" in ''|*[!0-9]*) hf_share=0 ;; esac

  # Saw log lines but parsed zero access requests -> the log is not JSON (console
  # format). Do NOT claim all-clear: mark unreadable so it never false-resolves.
  if [ "$hf_lines" -gt 20 ] && [ "$hf_total" -eq 0 ]; then R_STATE="unreadable"; return; fi
  [ "${HTTP_MIN:-0}" != "0" ] || return
  [ "$hf_total" -ge "$HTTP_MIN" ] || return
  hf_rate=$(( hf_total * 60 / WIN ))
  if [ "$hf_share" -ge "$HTTP_SHARE_PCT" ] && [ "$hf_ip" != "-" ]; then
    # One source holds most of it. A CDN address, a client that reached the box through
    # a proxy (its address came from a header, which a client can set), or one whose
    # requests mostly claim a good-bot User-Agent, is named but never blocked.
    if [ "$hf_exempt" = 1 ]; then
      MIT_NOTE=" [not blocked: $hf_ip did not connect directly, is a CDN address, or mostly claims to be a known bot]"
    else
      mitigate_ip "$hf_ip"
    fi
    R_STATE="raised"
    R_DETAIL="HTTP flood via ${hf_cid}: ${hf_ip} sent ${hf_top}/${hf_total} reqs (${hf_share}%, ~${hf_rate}/min) in ${WIN}s${MIT_NOTE}"
  elif [ "$HTTP_TOTAL_PER_MIN" != 0 ] && [ "$hf_rate" -ge "$HTTP_TOTAL_PER_MIN" ]; then
    # Many sources, none holding the share: a flood from many addresses, or real users.
    # It alerts and never blocks.
    R_STATE="raised"
    R_DETAIL="HTTP flood via ${hf_cid}: ${hf_total} reqs (~${hf_rate}/min) in ${WIN}s, no single source over ${HTTP_SHARE_PCT}% (busiest ${hf_ip} with ${hf_share}%), so nothing is blocked"
  fi
}

# --- check 4: SMTP connect burst (postfix logs from the mailserver container) -
check_smtp_flood() {
  R_STATE="ok"; R_SEV="$SMTP_SEVERITY"; R_DETAIL=""
  [ "$SMTP_ENABLE" = "1" ] || return
  command -v "$DOCKER_CMD" >/dev/null 2>&1 || return
  sf_cid="$SMTP_CONTAINER"
  if [ -z "$sf_cid" ]; then
    # As in check 3: a failed `docker ps` is unreadable, not "no mail server".
    if ! sf_ps=$("$DOCKER_CMD" ps --format '{{.Names}}' 2>/dev/null); then R_STATE="unreadable"; return; fi
    sf_cid=$(printf '%s\n' "$sf_ps" | grep -iE 'mail' | head -1)
  fi
  [ -n "$sf_cid" ] || return       # no mailserver -> inert
  [ "$LAST" -gt 0 ] || return      # first run -> baseline

  sf_raw=$("$DOCKER_CMD" logs --since "$LAST" "$sf_cid" 2>&1)
  if [ $? -ne 0 ]; then R_STATE="unreadable"; return; fi
  # postfix logs "connect from host[203.0.113.4]" per inbound connection. Anchor the IP
  # to the "connect from" host so the syslog PID (postfix/smtpd[1234]) is never
  # mistaken for a source address.
  sf_ips=$(printf '%s\n' "$sf_raw" | grep -E 'postfix/[a-z]*smtpd.*connect from' \
    | grep -oE 'connect from [^[]*\[[0-9a-fA-F:.]+\]' \
    | sed -E 's/.*\[//; s/\]$//' | awk 'NF')
  sf_dom=$(printf '%s\n' "$sf_ips" | _dominant)
  sf_total=$(printf '%s' "$sf_dom" | awk '{print $1}')
  sf_top=$(printf '%s' "$sf_dom" | awk '{print $2}')
  sf_ip=$(printf '%s' "$sf_dom" | awk '{print $3}')
  case "$sf_total" in ''|*[!0-9]*) sf_total=0 ;; esac
  case "$sf_top" in ''|*[!0-9]*) sf_top=0 ;; esac
  [ "${SMTP_MIN:-0}" != "0" ] || return
  if [ "$sf_total" -ge "$SMTP_MIN" ]; then
    sf_note=""
    if [ "$sf_total" -gt 0 ] && [ "$sf_ip" != "-" ]; then
      sf_share=$(( sf_top * 100 / sf_total ))
      [ "$sf_share" -ge "$SMTP_SHARE_PCT" ] && sf_note="; top ${sf_ip} (${sf_top}, ${sf_share}%)"
    fi
    sf_rate=$(( sf_total * 60 / WIN ))
    R_STATE="raised"
    R_DETAIL="SMTP connect burst on ${sf_cid}: ${sf_total} connects in ${WIN}s (~${sf_rate}/min)${sf_note}"
  fi
}

# --- run the checks ----------------------------------------------------------
check_conn_flood
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE conn-flood" ;;
  *) transition "conn-flood" "$R_STATE" "$R_SEV" "Connection flood" "$R_DETAIL" ;;
esac

check_net_volume
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE net-flood" ;;
  *) transition "net-flood" "$R_STATE" "$R_SEV" "Inbound network flood" "$R_DETAIL" ;;
esac

check_http_flood
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE http-flood" ;;
  *) transition "http-flood" "$R_STATE" "$R_SEV" "HTTP request flood" "$R_DETAIL" ;;
esac

check_smtp_flood
case "$R_STATE" in
  unreadable) UNREADABLE="$UNREADABLE smtp-flood" ;;
  *) transition "smtp-flood" "$R_STATE" "$R_SEV" "SMTP connect flood" "$R_DETAIL" ;;
esac

# --- aggregate "monitor unreadable" (one card, never a false all-clear) ------
if [ -n "$UNREADABLE" ]; then
  transition "monitor-unreadable-flood" "raised" "warning" "Flood monitor unreadable" \
    "could not read:${UNREADABLE}. Its signal is UNKNOWN this run (not clear)."
else
  transition "monitor-unreadable-flood" "ok" "warning" "Flood monitor unreadable" ""
fi

# --- record the run clock + report overflow ----------------------------------
# `flood-unreadable` names the checks that could not read this run, for nethersec-status.sh.
printf '%s\n' "${UNREADABLE# }" > "$STATE_DIR/flood-unreadable" 2>/dev/null || log "flood-unreadable write failed"
printf '%s\n' "$NOW" > "$STATE_DIR/flood-lastrun" 2>/dev/null || log "flood-lastrun write failed"
if [ "$OVERFLOW" -gt 0 ]; then
  log "per-run post cap ($MAX_POSTS) hit; $OVERFLOW report(s) suppressed this run"
fi
if [ "$DEFERRED" -gt 0 ]; then
  log "the hub did not answer; $DEFERRED more report(s) wait for the next run"
fi

exit 0
