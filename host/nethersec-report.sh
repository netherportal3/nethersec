#!/usr/bin/env sh
# nethersec-report.sh: send one report from this box. Every host script posts through
# this file, and you can call it from your own scripts too.
#
# By default it speaks the report protocol (docs/report-protocol.md) to a nethersec hub.
# It can also post straight to a Discord webhook, an ntfy topic, or any URL that takes
# JSON, for a box that runs without a hub.
#
# Env:
#   NETHERSEC_REPORT_URL     where to post (required). For the hub: https://<hub>/v1/report
#   NETHERSEC_REPORT_KEY     the key for this box's source (required for the hub; optional
#                            for ntfy and json, where it is sent as a bearer token if set;
#                            not used for Discord, whose webhook URL is the secret)
#   NETHERSEC_REPORT_FORMAT  hub (default) | discord | ntfy | json. A Discord webhook URL
#                            picks discord when this is unset.
#
# Usage:
#   nethersec-report.sh --kind security --source web1 --event ssh-auth-burst \
#       --severity warning --title "SSH login burst" --detail "2300 failed logins"
#   nethersec-report.sh --kind security --source web1 --event ssh-auth-burst --state resolved
#
# Flags:
#   --kind      uptime | security                (default: uptime)
#   --source    (required) this box's source name: a-z, 0-9 and '-', 1 to 40 characters
#   --event     (required) the check's name: a-z, 0-9, '.', '_' and '-', 1 to 64 characters
#   --state     triggered | resolved             (default: triggered)
#   --severity  critical | warning | info        (optional; empty means warning for
#               security and critical for uptime)
#   --title     optional title (cut to 120 characters)
#   --detail    optional detail (cut to 1500 characters, 64000 for the data events)
#   --group     optional grouping label (cut to 40 characters)
#
# The data events (reboot-pending, container-packages) need the hub's store. In the
# other formats they are skipped with a log line and exit 0.
#
# The key and the URL go to curl in a config read from stdin (`-K -`), never on its
# command line, where any local user could read them. Nothing here prints the key.
#
# Exit: 0 on a 2xx answer (or a skipped data event), 4 when the answer was a 403 (the
# key may not send this report, such as a data event from a `dm=` key), 1 when the
# report was not delivered for any other answer, 3 when no answer came back at all (no
# network, a timeout, nothing listening), 2 on a usage or config error. Only 0 counts as
# sent: a caller keeps any other report pending and sends it again on a later run.
set -u
LC_ALL=C; export LC_ALL

log() { echo "nethersec-report: $*" >&2; }

KIND="uptime"; SOURCE=""; EVENT=""; STATE="triggered"; SEVERITY=""; TITLE=""; DETAIL=""; GROUP=""

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,/^set -u/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    --kind|--source|--event|--state|--severity|--title|--detail|--group)
      [ $# -ge 2 ] || { log "$1 needs a value"; exit 2; } ;;
    *) log "unknown arg '$1'"; exit 2 ;;
  esac
  case "$1" in
    --kind)     KIND="$2" ;;
    --source)   SOURCE="$2" ;;
    --event)    EVENT="$2" ;;
    --state)    STATE="$2" ;;
    --severity) SEVERITY="$2" ;;
    --title)    TITLE="$2" ;;
    --detail)   DETAIL="$2" ;;
    --group)    GROUP="$2" ;;
  esac
  shift 2
done

# A mistyped --kind must fail rather than turn a security report into an uptime blip.
case "$KIND" in uptime|security) ;; *) log "--kind must be uptime or security (got '$KIND')"; exit 2 ;; esac
case "$STATE" in triggered|resolved) ;; *) log "--state must be triggered or resolved (got '$STATE')"; exit 2 ;; esac
case "$SEVERITY" in ''|critical|warning|info) ;; *) log "--severity must be critical, warning or info (got '$SEVERITY')"; exit 2 ;; esac
printf '%s' "$SOURCE" | grep -Eq '^[a-z0-9][a-z0-9-]{0,39}$' \
  || { log "--source must match ^[a-z0-9][a-z0-9-]{0,39}\$ (got '$SOURCE')"; exit 2; }
printf '%s' "$EVENT" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,63}$' \
  || { log "--event must match ^[a-z0-9][a-z0-9._-]{0,63}\$ (got '$EVENT')"; exit 2; }

URL="${NETHERSEC_REPORT_URL:-}"
KEY="${NETHERSEC_REPORT_KEY:-}"
[ -n "$URL" ] || { log "NETHERSEC_REPORT_URL is not set"; exit 2; }

FORMAT="${NETHERSEC_REPORT_FORMAT:-}"
if [ -z "$FORMAT" ]; then
  case "$URL" in
    https://discord.com/api/webhooks/*|https://*.discord.com/api/webhooks/*|https://discordapp.com/api/webhooks/*|https://*.discordapp.com/api/webhooks/*) FORMAT=discord ;;
    *) FORMAT=hub ;;
  esac
fi
case "$FORMAT" in hub|discord|ntfy|json) ;; *) log "NETHERSEC_REPORT_FORMAT must be hub, discord, ntfy or json (got '$FORMAT')"; exit 2 ;; esac
if [ "$FORMAT" = hub ] && [ -z "$KEY" ]; then
  log "NETHERSEC_REPORT_KEY is not set (the hub format needs this box's key)"; exit 2
fi

DATA_EVENT=0
case "$EVENT" in reboot-pending|container-packages) [ "$KIND" = security ] && DATA_EVENT=1 ;; esac
if [ "$DATA_EVENT" = 1 ] && [ "$FORMAT" != hub ]; then
  log "skipped data event $EVENT: the $FORMAT format has nowhere to store it"
  exit 0
fi

# Text is cut to the protocol's limits, newlines and tabs become spaces, and every byte
# outside printable ASCII is dropped, so the body is always valid JSON and the hub never
# refuses it for length.
clean() {  # $1=text $2=max characters
  printf '%s' "$1" | tr '\n\r\t' '   ' | tr -cd '\40-\176' | cut -c "1-$2"
}
# JSON string escape (also the escape for a double-quoted value in a curl config).
jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

DETAIL_MAX=1500; [ "$DATA_EVENT" = 1 ] && DETAIL_MAX=64000
TITLE=$(clean "$TITLE" 120)
DETAIL=$(clean "$DETAIL" "$DETAIL_MAX")
GROUP=$(clean "$GROUP" 40)

# The severity the hub would apply, for the formats that have to show it themselves.
EFF_SEV="$SEVERITY"
if [ -z "$EFF_SEV" ]; then
  if [ "$KIND" = uptime ]; then EFF_SEV=critical; else EFF_SEV=warning; fi
fi

CT="application/json"
case "$FORMAT" in
  hub|json)
    BODY=$(printf '{"v":1,"kind":"%s","source":"%s","event":"%s","state":"%s","severity":"%s","title":"%s","detail":"%s","group":"%s"}' \
      "$KIND" "$SOURCE" "$EVENT" "$STATE" "$SEVERITY" "$(jesc "$TITLE")" "$(jesc "$DETAIL")" "$(jesc "$GROUP")")
    ;;
  discord)
    if [ "$STATE" = resolved ]; then
      if [ "$KIND" = security ]; then HEAD="RESOLVED (reported by the box, check it yourself)"; else HEAD="RESOLVED"; fi
    else
      HEAD=$(printf '%s' "$EFF_SEV" | tr 'a-z' 'A-Z')
    fi
    LINE1="$HEAD $SOURCE $EVENT${TITLE:+: $TITLE}"
    CONTENT=$(jesc "$LINE1")
    if [ "$STATE" = triggered ] && [ -n "$DETAIL" ]; then CONTENT="$CONTENT\\n$(jesc "$DETAIL")"; fi
    # allowed_mentions with an empty parse list: nothing in the text can ping anyone.
    BODY=$(printf '{"content":"%s","allowed_mentions":{"parse":[]}}' "$CONTENT")
    ;;
  ntfy)
    CT="text/plain"
    if [ "$STATE" = resolved ]; then
      NT_TITLE="Resolved: $SOURCE $EVENT"; NT_PRIO=2
      BODY="${TITLE:-$EVENT} on $SOURCE is reported fixed."
    else
      NT_TITLE="$SOURCE: ${TITLE:-$EVENT}"
      case "$EFF_SEV" in critical) NT_PRIO=5 ;; warning) NT_PRIO=3 ;; *) NT_PRIO=2 ;; esac
      BODY="${DETAIL:-${TITLE:-$EVENT}}"
    fi
    NT_TITLE=$(clean "$NT_TITLE" 200)
    ;;
esac

# The curl config on stdin: the URL, the headers (the key among them) and the body.
cfg() {
  printf 'url = "%s"\n' "$(jesc "$URL")"
  printf 'header = "Content-Type: %s"\n' "$CT"
  case "$FORMAT" in
    hub) printf 'header = "Authorization: Bearer %s"\n' "$(jesc "$KEY")" ;;
    json|ntfy) [ -n "$KEY" ] && printf 'header = "Authorization: Bearer %s"\n' "$(jesc "$KEY")" ;;
  esac
  if [ "$FORMAT" = ntfy ]; then
    printf 'header = "Title: %s"\n' "$(jesc "$NT_TITLE")"
    printf 'header = "Priority: %s"\n' "$NT_PRIO"
  fi
  printf 'data-raw = "%s"\n' "$(jesc "$BODY")"
}

# The answer's body, then the HTTP status on its own last line.
NL='
'
RESP=$(cfg | curl -sS --max-time 15 -w "${NL}%{http_code}" -K - 2>&1)
RC=$?
CODE=$(printf '%s\n' "$RESP" | tail -n 1)
case "$CODE" in
  2[0-9][0-9]) [ "$RC" -eq 0 ] && exit 0 ;;
esac
# Never print the config: it holds the key. The hub never echoes the key back, and
# anything that looks like a URL is masked, since a webhook URL is itself a secret.
MSG=$(printf '%s\n' "$RESP" | sed '$d' | tr '\n\r\t' '   ' | sed 's#[A-Za-z][A-Za-z0-9+.-]*://[^ ]*#<url>#g' | cut -c 1-300)
log "not delivered ($FORMAT, event $EVENT): curl exit $RC, HTTP ${CODE:-none}${MSG:+: $MSG}"
# A 403 has its own code: the same report from the same key gets the same answer, so a
# caller can wait longer before it sends that one again. No HTTP status at all: nothing
# answered. The callers stop posting for the rest of their run then, so a hub that is
# down costs one timeout a run, not one per report.
case "$CODE" in
  403) exit 4 ;;
  [1-5][0-9][0-9]) exit 1 ;;
esac
exit 3
