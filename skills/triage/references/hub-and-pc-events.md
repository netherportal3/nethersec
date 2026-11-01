# Hub cards and PC reports

## Repo advisory cards (`kind: repo`)

From the hub's scan of lockfiles on each watched repo's default branch (npm, pnpm, Yarn, Bun,
pip exact pins, uv, Poetry). One card per advisory and package, listing each repo it is new in
with the installed version and the version that fixes it. A repo it turns up in on a later scan
gets its own card.

- **Where:** critical advisories and malware go to `#nethersec-critical` and ping (a critical
  one that affects only dev dependencies pings only with `ping_dev_only` on); others at the
  alert level (High and above by default) go to `#nethersec-alerts`. A repo's first scan only
  records what is already open, in one summary. At most 10 cards per scan; the rest are listed
  in one summary message.
- **Confirm:** `/nethersec findings repo:<owner/name>`, or the card's `repos` in `/v1/state`.
  Check the advisory itself: databases can lag a same-day advisory, and the fixed version can
  read "not listed" at first.
- **Fix:** the `dependency-sweep` skill, one PR per repo.
- **Closes:** by itself once the advisory is gone from every repo on the card (after the fix is
  merged to the default branch and a scan ran; `/nethersec scan` runs one now). The status
  channel says so.
- **Buttons:** Acknowledge (admins and the watcher role); Mute advisory (admins) stops alerts for
  that advisory in every repo. A mute does not fix anything: use it only when the advisory does
  not apply anywhere, and say why.
- **Malware** always gets its own critical card. If any machine or CI run installed the bad
  version, treat that machine as compromised: stop, tell the person, and follow the package
  advisory's own cleanup steps before you rotate credentials (some worms watch for a revoked
  token and then destroy data).

Problems the scan hits (a repo it cannot read two scans in a row, a lockfile too big to parse,
an advisory source down, an organization that needs SSO for the token) show on the status
board in `#nethersec-status`, not as cards. While one lasts, nothing in that repo or ecosystem
is marked fixed.

## Watch cards (`kind: watch`)

Posted by the hub's hourly advisory watch and container check (`docs/hub/watch.md`). They have
Acknowledge and Resolve buttons (admins and the watcher role); there is no Mute. A card that
closes by itself and is resolved while its problem is still there opens again as a new card.

| Title | Severity | Means | Closes |
|---|---|---|---|
| `Exploited in the wild: <CVE> in <component>` | critical, pings | CISA's KEV catalog lists a bug in a component from `watch.json`. A fix may not be out yet. | Not by itself. Resolve once every place is handled; it does not come back. Acknowledged, it closes by itself after 90 days. |
| `Critical advisory for <component>: ...` / `High advisory ...` / `Security advisory ...` | critical pings / warning | A component's feed published an advisory. Advisories that share one fixed version share one card. | Not by itself: it cannot see what you installed. Resolve once handled; it does not come back. Acknowledged, it closes by itself after 90 days. |
| `Critical kernel bug with no Ubuntu security fix yet: <CVE>` (or `<N> critical kernel bugs ...`) | critical, pings (the feed's first read is one quiet card) | A CVSS 9.0 or higher, network-reachable kernel CVE that a listed Ubuntu release has no released fix for. | By itself, once every listed release is fixed or not affected. Resolved before that, it opens again within about 6 hours and pings again. Mitigated but not fixed: Acknowledge. |
| `<Critical or High> CVE(s) in <package> in container image <image>` | warning, never pings | A published container's OS packages have a fixable critical or high CVE. Lists the boxes and containers running the image. | By itself, once every listed container runs the fix (or is gone). Resolved before that, it opens again within about 6 hours. |
| `Can't read <name> advisories` (also `Linux kernel`) | warning | That feed failed every read for a day. Not a clean bill of health. | By itself, after a good read. Resolved before that, it opens again within about 6 hours. |
| `Can't check container packages` | warning | A day of runs that could not read the package lists or OSV. | By itself, when a run gets through. Resolved before that, it opens again within about 6 hours. |
| `watch.json has a problem, so the advisory watch and container check are off` | warning | The file did not parse or check. The card lists every problem. | By itself, on the next clean read. Resolved before that, it opens again on the next hourly run. |

- **Exploited, advisory and kernel cards:** the `advisory-response` skill.
- **Container cards:** rebuild the image on a patched base (or pull again when the card says the
  tag moves) and recreate the container on each box listed, one box at a time. Language
  packages inside the image (npm, pip, Go) are not in this check.
- **A feed that cannot be read:** fetch the URL yourself from the hub host. Redirects are
  refused, so a feed that moved needs its new address in `watch.json`.
- An advisory or KEV card stays open in `/v1/state` until a person resolves it (or 90 days after
  it was acknowledged, `advisoryCards.closeAcknowledgedAfterDays` in `watch.json`, `0` for never),
  and counts toward the 300 open watch cards. `acked: true` is how you tell handled ones apart.
- **Watch cards are full:** at 300 open watch cards, new ones are refused (a critical one may
  still open, up to 50 past that). The status board shows "Watch cards are full" with when it
  started, `/v1/state` has `watch.refusedSince`, and the modules try the refused cards again
  every hourly run. List them with
  `/nethersec alerts kind:watch` (or `nethersec_alerts` with `kind: watch`) and resolve the
  handled advisory and KEV cards; the notice goes once there is room.

## PC scanner reports

A PC reports to one person by direct message (a `dm=` key on the hub) or to a Discord webhook.
There is no card, no button and no Resolve. A report goes out when a check turns bad or good,
when a bad one gains an item or rises in severity, and as a weekly reminder while it stays bad.
Confirm on the PC with `node $env:USERPROFILE\.nethersec-pc\pc-security-report.mjs --dry-run`
(`docs/pc/README.md`).

| Event | Means | Fix |
|---|---|---|
| `exploited` | A CISA KEV entry matches something installed. **Critical** when an update is waiting (or it could not check for one); a warning notice when the newest version is already installed. | Install the update (Windows Update, or `winget upgrade --id <id>`). It clears only on proof: the version went up and no update waits, or the app is gone. |
| `windows-updates` | A security update is not installed 7 days after release. Also says when a restart is pending or updates are paused. | Settings, Windows Update; restart if pending. |
| `defender` | Defender off, real-time protection off, or definitions older than 3 days. Passive mode under another antivirus is fine. | Turn it back on; update definitions. Find out why it was off. |
| `firewall` | A firewall profile is off. | Turn it on. Find out why it was off. |
| `runtimes` | Node is behind on a security release of its major or past end of life, Go is behind on a patch release or on a line that is no longer supported, or Java (Azul Zulu) is behind Azul's newest build of its major. | Update the runtime. |
| `apps-behind` | Watched apps have a newer version in winget for 7 days. | `winget upgrade --id <id>` (or the `update` command in the report). |
| `apps-eol` | A package listed as end of life is installed. | Replace or remove it. |
| `wsl-updates` | A running WSL distro has `-security` upgrades, two daily checks in a row. | Inside the distro: `sudo apt-get upgrade`. |
| `monitor-unreadable` | A check could not read for over 2 days. Unknown, not clear. | Read `last-run.json` (`unreadable` names the check and why). winget, network and a bad `watch.json` are the usual causes. |

A PC on a `dm=` key whose messages stop: the hub answers 503 when it cannot deliver the direct
message (the person left the shared server, or blocks messages from the bot), and the PC tries
again next run.
