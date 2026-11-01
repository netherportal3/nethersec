# The hub's HTTP API

The hub serves three endpoints on `NETHERSEC_LISTEN` (default `127.0.0.1:8787`), over plain HTTP.
Put it behind HTTPS or on a private network (see [README.md](README.md#reaching-the-hub-from-servers-and-pcs)).
Every answer the hub writes is JSON with `Cache-Control: no-store`. A request that Node refuses
before the hub sees it (malformed, or too slow) gets Node's own plain answer instead.

| Endpoint | Token | What it is |
| --- | --- | --- |
| `POST /v1/report` | a report key | A box or PC sends one report. |
| `GET /v1/state` | `NETHERSEC_API_TOKEN` | Open alerts, hosts and stored data, for scripts and agents. |
| `GET /v1/health` | none | `{"ok":true}` while the hub is up. |

Any other path is 404, and a wrong method is 405 with an `Allow` header.

## POST /v1/report

The request and its rules are in [the report protocol](../report-protocol.md). The checks run in
this order, and the first one that fails decides the answer:

| Status | When | Body |
| --- | --- | --- |
| 401 | No `Authorization: Bearer <key>`, or a key that is not in `keys.txt`. Checked before the body is read. | `{"error": "..."}` |
| 413 | The body is over 100,000 bytes. | `{"error": "..."}` |
| 400 | The body is not JSON, or breaks a rule. `field` names the field: `body`, `v`, `kind`, `source`, `event`, `state`, `severity`, `title`, `detail` or `group`. | `{"error": "...", "field": "..."}` |
| 403 | The key belongs to another source, or a `dm=` key sent a data event. | `{"error": "..."}` |
| 429 | Over a rate limit, or a cap is full (see below). `Retry-After` says when to try again, in seconds. | `{"error": "..."}` |
| 202 | Done (see `result`). | `{"accepted": true, "result": "..."}` |
| 503 | Not delivered: Discord is not reachable, the hub is not set up yet, Discord did not take the post or edit, or the data could not be saved. Send the same report again on a later run. | `{"error": "..."}` |

One 400 comes later than the table shows: a `container-packages` report whose `detail` has no
usable `ctr=` (or, when triggered, no usable `img=`) is refused after the rate limit, with
`field` `detail`.

The hub never echoes the key, the title or the detail back.

`result` on a 202 says what happened:

| `result` | Meaning |
| --- | --- |
| `posted` | A new card. |
| `edited` | The open card was edited in place. |
| `unchanged` | The open card already shows this, or a security card already says the box reports it fixed; nothing was edited. |
| `noted` | An `info` report with no open card: a note in the status channel. |
| `already-noted` | An `info` report the same as one noted in the last hour (same check, title, detail and group). Nothing was posted. |
| `reported-fixed` | A resolved security report: the card now says the box reports it fixed, and stays open. |
| `closed` | A resolved uptime report closed the card. |
| `nothing-open` | A resolved report with no open card. Nothing to do. |
| `muted` | A person muted this check, and no card is open for it. Nothing was posted. |
| `dm` | A `dm=` key's report, sent as one direct message. |
| `stored` | A data event, stored. |
| `cleared` | A resolved data event: its record was removed. |

A cap that is full is answered 429 with `Retry-After: 3600`: 300 open host cards in all or 30 for
one source, 200 container package lists in all or 50 for one source, and 200 sources with a
pending reboot. Resolving cards
(or a box reporting a container gone) makes room. The full list of caps is in
[README.md](README.md#limits).

## GET /v1/state

Off (404) until `NETHERSEC_API_TOKEN` is set on the hub. With it set, send
`Authorization: Bearer <NETHERSEC_API_TOKEN>`; anything else is 401. The token is compared in
constant time. A report key is never accepted here, and this token is never accepted for reports.

The answer is read-only. Times are ISO 8601 strings in UTC. Every list holds at most 1,000 items.

```json
{
  "v": 1,
  "generatedAt": "2026-10-05T10:00:00.000Z",
  "discord": { "ready": true, "setUp": true },
  "repos": {
    "scanning": "on",
    "watched": 12,
    "open": { "critical": 0, "high": 2, "moderate": 5, "low": 1 },
    "lastScanAt": "2026-10-05T09:31:02.000Z"
  },
  "cards": [
    {
      "kind": "security",
      "id": "3f2a9c1b7e",
      "severity": "warning",
      "title": "SSH auth burst",
      "detail": "2312 failed SSH logins since last check, top 203.0.113.7",
      "source": "web1",
      "event": "ssh-auth-burst",
      "group": null,
      "repos": null,
      "url": null,
      "openedAt": "2026-10-05T09:58:00.000Z",
      "updatedAt": "2026-10-05T09:58:00.000Z",
      "acked": false,
      "muted": false,
      "reportedFixed": false
    }
  ],
  "watch": { "open": 4, "max": 300, "refusedSince": null, "lastRefusedAt": null },
  "hosts": [
    { "source": "web1", "firstReportAt": "2026-09-01T12:00:00.000Z", "lastReportAt": "2026-10-05T09:58:00.000Z", "reports": 57, "open": 1 }
  ],
  "rebootPending": [
    {
      "source": "db1",
      "since": "2026-09-28T03:10:00.000Z",
      "receivedAt": "2026-10-05T03:10:00.000Z",
      "stale": false,
      "checked": true,
      "livepatch": false,
      "packages": ["linux-image-generic", "openssl"],
      "more": 3,
      "covered": 1,
      "uncovered": 0
    }
  ],
  "containers": [
    {
      "box": "web1",
      "container": "api",
      "image": "ghcr.io/example/api:1.4",
      "imageId": "0123456789ab",
      "builtAt": "2026-08-20T10:00:00.000Z",
      "os": "debian",
      "osVersion": "12",
      "pm": "dpkg",
      "packages": 214,
      "more": 0,
      "receivedAt": "2026-10-05T03:12:00.000Z"
    }
  ]
}
```

| Field | What it is |
| --- | --- |
| `v` | The version of this shape, `1`. A field may be added without a new version; one is never removed or changed without one. |
| `discord.ready` | The bot is logged in to Discord now. |
| `discord.setUp` | `/nethersec setup` has run. |
| `repos.scanning` | `on`, `paused`, or `off` (no `GITHUB_TOKEN`). |
| `repos.watched`, `repos.open` | Repos watched at the last scan, and their open advisories by severity. |
| `repos.lastScanAt` | When the last scan finished, or `null`. |
| `cards` | Every open card, most severe first, then the most recently updated. |
| `cards[].kind` | `repo` (an advisory in your repos), `security` or `uptime` (a host report), or `watch` (a watch module's card). |
| `cards[].id` | The card's id, as the hub knows it. |
| `cards[].severity` | For `repo`: `critical`, `high`, `moderate` or `low`. For the others: `critical`, `warning` or `info`. |
| `cards[].title`, `cards[].detail` | For host cards, what the box sent (`title` is the event when the box sent none). For watch cards, the module's title and body. For repo cards, the advisory id, package and title; `detail` is empty. |
| `cards[].source`, `event`, `group` | The host report's fields, or `null`. |
| `cards[].repos` | For `repo` cards, the repos where the advisory is still open; otherwise `null`. |
| `cards[].url` | A link for the card (the advisory, or the watch card's link), or `null`. |
| `cards[].acked`, `muted` | A person pressed Acknowledge or Mute. |
| `cards[].reportedFixed` | A security card whose box sent `resolved`, or a container image card the boxes report fixed; it waits for a person to press Resolve. |
| `watch` | The open watch cards (`open`) against the most allowed (`max`). `refusedSince` is when new watch cards started being refused because `max` are open, and `lastRefusedAt` the latest refusal; both are `null` while there is room. Resolving watch cards makes room. |
| `hosts` | Every source that has reported (the hub keeps up to 500), with its first and last report, its report count, and its open cards. |
| `rebootPending` | The `reboot-pending` data of each box with a reboot pending. `since` is when the box first saw it (`null` when not sent); `stale` is true after 2 days with no report; `covered` and `uncovered` are `null` unless `checked`. |
| `containers` | One summary per stored `container-packages` list: the package count, not the packages. `os` and `osVersion` are empty when the box did not send them; `imageId` and `builtAt` are `null` then. |

## GET /v1/health

No token. Answers `200 {"ok":true}` while the hub is up, also before it logs in to Discord. It
says nothing about Discord or the boxes; use `/v1/state` for that.
