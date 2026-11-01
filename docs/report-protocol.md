# Report protocol, version 1

How a host script, the PC scanner, or your own script sends a report to the hub. This is the
only interface between the parts of nethersec.

## The request

```
POST /v1/report
Authorization: Bearer <key>
Content-Type: application/json
```

The hub listens on plain HTTP (`NETHERSEC_LISTEN`, default `127.0.0.1:8787`). Put it behind
HTTPS (a reverse proxy) or reach it over a private network (a VPN or tailnet). A key sent over
plain HTTP on the open internet can be read on the way.

The body is one flat JSON object. Every field is a string except `v`. Unknown fields are ignored.

| Field | Required | Rule |
|---|---|---|
| `v` | no | `1`. Absent means 1. |
| `kind` | yes | `security` or `uptime` |
| `source` | yes | `^[a-z0-9][a-z0-9-]{0,39}$`. Must equal the source the key was made for. |
| `event` | yes | `^[a-z0-9][a-z0-9._-]{0,63}$`, the name of the check |
| `state` | no | `triggered` (default) or `resolved` |
| `severity` | no | `critical`, `warning`, `info`, or empty. Empty means `warning` for `security` and `critical` for `uptime`. Ignored on `resolved`. |
| `title` | no | up to 120 characters |
| `detail` | no | up to 1,500 characters, or 64,000 for the data events below |
| `group` | no | up to 40 characters, a label to group cards by |

The whole body is at most 100 kB. Tabs and line breaks become spaces, and other control characters
are stripped. The hub shows `title` and `detail` as plain text and never lets them mention a role
or a user.

## Keys

Every key belongs to exactly one source. The hub stores only the SHA-256 of each key, so a copy
of the hub's files cannot be used to send reports. A key from `key new` is 32 random bytes as 64
hex characters.

A key has two optional flags, set when it is made:

- `page`: a `critical` report from this source pings the watcher role (unless `ping_critical` is
  off in `/nethersec settings`). Without it, a critical report is posted in the critical channel
  with its color but pings nobody. Give `page` to servers, not to devices that can be carried off.
- `dm=<Discord user ID>`: reports from this source go to that one person as a direct message
  and nowhere else (no channel, no card, no ping). For a personal PC. `page` and `dm=` cannot be
  combined; a key with both is refused at load.

On a Linux box the key lives in a file readable only by its owner (mode 600) and is passed to
`curl` on stdin (`-K -`), never on the command line. The PC scanner keeps it in its folder in the
user's profile, encrypted for that Windows account (DPAPI), and sends it from memory.

## Responses

| Status | Meaning | What the sender does |
|---|---|---|
| 202 | Accepted: the card was posted or edited, or the data was stored | Mark the report sent |
| 400 | The body broke a rule above; the reply says which field | Log it. The same body gets the same answer, so fix the sender |
| 401 | Missing or unknown key | Log it, and send it again on the next run (the hub may not have the key's line yet) |
| 403 | The key is not allowed this report (another source, or a data event from a `dm=` key) | Log it |
| 413 | Body too large | Log it |
| 429 | Rate limited; `Retry-After` says when | Retry on the next run |
| 503 | Not delivered (Discord unreachable, hub not set up yet, or the data could not be saved) | Retry on the next run |

A 202 body says what the hub did (`{"accepted": true, "result": "posted"}`, or `edited`, `noted`,
`reported-fixed` and others); [the hub's API doc](hub/api.md) lists them and the order the checks
run in. A 429 also answers a full store (too many open cards or stored lists), with
`Retry-After: 3600`.

A sender treats only a 2xx as sent. Anything else leaves the report pending, so a later run sends
it again. The hub never echoes the key, the detail or the title back.

The host scripts do this for every answer that is not a 2xx, and when no answer comes back at all
(no network, a timeout). They change their state (a raised check, a re-surface stamp, a cleared
check) only after a 2xx, so a refused `resolved` is sent again too. There are two exceptions.
The one-shot info notes (`security-updates-applied`, `apply-applied`): one that is not delivered
is not sent again. And a data event that gets a 403 (from a `dm=` key): the detector logs it
once and sends the same data again only after its usual resend interval (about 20 hours), or at
once when the data changes. `nethersec-report.sh` checks and cuts every field to the rules
above before it sends, so a 400 or 413 from the hub points at a bug in the sender. It exits 0
for a 2xx, 4 for a 403, 1 for any other answer and 3 when nothing answered. After a 3, the
detector and the flood detector leave the rest of that run's reports for the next run, so a hub
that is down costs them one timeout a run.

## What the hub does with a report

A report's identity is `<kind>:<source>:<event>`.

- **Triggered, no open card:** a new card, unless a person muted the check (an `info` report never
  makes one; see below). `critical` goes to the critical channel (pings the role only if the key
  has `page`), `warning` to the alerts channel with no ping, `info` to the status channel as a note
  with no card. An `info` report the same as one noted in the last hour (same identity, title,
  detail and group) is answered 202 and not posted again.
- **Triggered, card already open:** the card is edited in place. It pings again only when the
  severity went up to `critical`.
- **Resolved, kind `security`:** the card gets a "the box reports this is fixed" line, and stays
  open until a person presses Resolve. A box cannot close its own security alert, so a box that
  was taken over cannot quietly clear the alert about it.
- **Resolved, kind `uptime`:** the card closes.

Rate limits: 25 alert reports a minute per source and 100 a minute in total; the data events
have their own limits (30 a minute per source, 150 in total), so a box listing its containers
never crowds out its alerts. A `dm=` source is also limited to 15 reports an hour. A report the
rate limits refuse counts toward none of them, so a source over its own limit cannot use up the
total that the other sources share.

## Data events

Two `security` events are data, not alerts. They are stored and never become a card by
themselves. Their `detail` is a list of `key=value` tokens separated by spaces, with no spaces
inside a value.

### `reboot-pending`

Sent by the host detector when the box has a reboot pending, when that data changes, and about
every 20 hours otherwise; `resolved` once the box has rebooted.

```
v=1 since=<epoch s> checked=yes|no livepatch=on|off pkgs=<name>,<name>,... more=<n>
    [hc_covered=<n> hc_uncovered=<n>]   (only when checked=yes)
```

`since` is when the box first saw the reboot pending, `pkgs` the staged packages (at most 12, or
`-` for none, with `more` counting the rest), `livepatch` whether Livepatch is on, and
`checked=no` when the CVE lookup could not finish. `hc_covered` and `hc_uncovered` count the High
or Critical CVEs fixed by the staged updates that already protect the box (through Livepatch or a
restarted service) and the ones that still need the reboot. The hub posts one weekly summary of every box with a
reboot pending to the status channel.

### `container-packages`

One report per running container that publishes a port or uses the host network.

```
v=1 ctr=<container name> img=<image ref> iid=<image id hex> built=<epoch s>
os=<os-release ID> osver=<VERSION_ID> pm=dpkg|apk|none more=<n>
pkgs=<source package>@<version>,...   (or pkgs=- when there is none)
```

Packages are source packages (the dpkg `Source:` field, the Alpine origin), because OSV keys
Debian, Ubuntu and Alpine advisories on those. A `resolved` report with the same `ctr=` says the
container is gone or no longer publishes a port. The hub matches the lists against OSV and opens
one card per image that has a fixable critical or high CVE.

## Without a hub

The host scripts can also post straight to a Discord webhook, an ntfy topic, or any URL that takes
JSON (`NETHERSEC_REPORT_FORMAT=discord|ntfy|json`). There is no card state, no Resolve button and
no rate limit then, and the two data events are skipped. The box still reports only on a change.

## Reading the hub's state

`GET /v1/state` with `Authorization: Bearer <NETHERSEC_API_TOKEN>` returns the hub's open
alerts, hosts and stored data as JSON, for scripts and agents. It is read-only, it uses its own token
(never a box key), and it is off while `NETHERSEC_API_TOKEN` is unset. `GET /v1/health` needs no
token and answers `{"ok":true}` while the hub is up.
