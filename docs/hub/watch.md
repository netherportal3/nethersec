# The advisory watch and the container check

The hub runs two checks every hour, next to its lockfile scan:

- The **advisory watch** reads the security feeds of the software you list in `watch.json`
  (servers, daemons, agents: things no lockfile names), CISA's catalog of bugs exploited in the
  wild, and, if you turn it on, a feed of critical Linux kernel bugs that Ubuntu has not fixed yet.
- The **container check** matches the OS packages inside your published containers, as your
  boxes report them, against [OSV](https://osv.dev).

Both only open, edit and close cards. Neither acts on a box. The code is in `hub/src/watch/` and
its tests in `hub/test/watch/`. Which cards close by themselves and which need a person to press
Resolve is in [Resolving a watch card](#resolving-a-watch-card).

## watch.json

The watch reads `<DATA_DIR>/watch.json`. Without the file you get the defaults: no components
(so no advisory feeds and no KEV feed), the kernel feed off, and the container check on. A file
that is there but wrong is an error that names every problem (`WatchConfigError`), never the
defaults, so a typo cannot turn a feed off quietly. Keys that start with `_` are notes and are
ignored; any other unknown key is an error.

A starting point is in [`hub/src/watch/watch.example.json`](../../hub/src/watch/watch.example.json).
Copy it, then keep only what you run and say where it runs.

```json
{
  "components": [
    { "id": "kev", "name": "CISA KEV", "feed": { "kind": "kev" } },
    { "id": "openssh", "name": "OpenSSH", "runsOn": "Every server", "kev": [{ "product": "^OpenSSH\\b" }] },
    {
      "id": "docker",
      "name": "Docker Engine",
      "runsOn": "web1, db1",
      "feed": { "kind": "github", "repo": "moby/moby" },
      "kev": [{ "vendor": "^Docker\\b" }]
    },
    {
      "id": "postgres",
      "name": "PostgreSQL",
      "runsOn": "db1",
      "feed": { "kind": "rss", "url": "https://www.postgresql.org/news/pgsql.rss", "match": "\\breleased\\b|\\bsecurity\\b" }
    }
  ],
  "kernel": { "ubuntu": ["24.04"], "runsOn": "Every server" },
  "containers": { "enabled": true },
  "advisoryCards": { "closeAcknowledgedAfterDays": 90 }
}
```

### components

Each entry is one thing you run.

| Key | Required | What it is |
|---|---|---|
| `id` | yes | 1 to 40 lowercase letters, digits or dashes. Used in card ids and state names, so keep it stable. `linux-kernel` is taken by the kernel feed. |
| `name` | yes | What cards call it, up to 60 characters. |
| `runsOn` | no | Where it runs, up to 500 characters. Cards show it, because whether an advisory matters depends on where the software is. |
| `feed` | no | Where its advisories are published (below). Without a feed, the component is watched only through the KEV feed. |
| `kev` | no | How CISA's catalog names it: a list of `{ "vendor": "...", "product": "..." }`. |

A component needs a `feed`, `kev` names, or both.

**Feeds:**

- `{ "kind": "github", "repo": "owner/repo" }` reads the repo's published GitHub security
  advisories, the newest 20 each run. It gives a severity and the fixed versions. Many projects
  publish advisories somewhere else; for those, use an RSS feed if there is one.
- `{ "kind": "rss", "url": "https://...", "match": "..." }` reads an RSS 2.0 feed of security
  bulletins or release news, up to its first 500 items. Without `match`, every item is treated
  as an advisory. With `match` (a regular expression, case-insensitive), only items whose title or
  one of whose `<category>` values matches are; the rest are recorded without a card. Use `match`
  for a news feed that mixes security releases with other posts. The fixed version is read from
  text like "1.4.2 or later" when the item has it. Each field of an item (its title, its
  description) is read up to its first 20,000 characters, so a fixed version named after that is
  not found.
- `{ "kind": "kev" }` reads CISA's [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  and matches it against the `kev` names of every other component. Give it to one component
  only, with no `kev` names of its own.

**KEV names.** `vendor` and `product` are regular expressions (case-insensitive) matched against
the catalog's `vendorProject` and `product` fields, trimmed. A matcher needs at least one of the
two, and every one it gives must match. Several matchers on one component are alternatives. Check
a new pattern against the catalog: `"product": "Redis"` also matches products that only contain
the word, and `"^Linux$"` as the vendor keeps Android kernel entries out.

### kernel

`{ "ubuntu": ["22.04", "24.04"], "runsOn": "..." }` turns the kernel feed on for those Ubuntu
releases. A release is a version this knows (the LTS releases 16.04 to 26.04, and 24.10, 25.04
and 25.10) or a codename like `noble`, which also covers a release newer than this code. Leave
`kernel` out to keep the feed off.

### containers

`{ "enabled": false }` turns the container check off. It is on when the key is absent. Turning it
off leaves cards it opened as they are; close them by hand with Resolve.

### advisoryCards

`{ "closeAcknowledgedAfterDays": 90 }` closes an advisory or KEV card by itself once that many days
have passed since a person pressed Acknowledge on it. The default is 90 days; `0` turns it off;
otherwise it takes 7 to 3650 days. A card nobody acknowledged never closes this way, and kernel,
container and "can't read" cards are not touched. It runs after each hourly advisory run, at most
25 cards a run, the oldest acknowledgment first. The closed card says why it closed. Nothing here
checks whether you installed the fix, so this only tidies away notices a person has already seen.
It keeps the open watch cards from filling up when people acknowledge cards and never resolve them.

Container cards that the boxes report fixed do not get this, acknowledged or not. The only sign of
that fix is the boxes' own word, and closing on it after a delay would still let a box close an
alert about itself. A host security card a box reports fixed does not close on a timer either.
They are kept from piling up unseen instead: they are not sent again, the status board counts
them ("reported fixed and waits for Resolve"), and they count toward the cap on open watch cards:
the "Watch cards are full" notice says how many of the open cards they are.

## The advisory watch

### What gets a card

| What is new | Card |
|---|---|
| A critical advisory | Critical card that pings |
| A high advisory, or a bulletin with no severity (most RSS items) | Quiet warning card |
| A medium or low advisory | None. Counted in the run report as `belowThreshold` |
| An RSS item that `match` skips | None. Counted as `skipped` |
| A KEV entry for a listed component | Critical card that pings, one per CVE, whether or not a fix is out |
| A KEV entry for anything else | None. Counted as `skipped` |
| A critical kernel bug with no Ubuntu fix (below) | Critical card that pings (a quiet card on the feed's first read) |

What a feed says (a title, a summary, a fixed version, a product name) is shown on the card as
typed: it cannot format the card or hide a link. So is what NVD and Ubuntu say on a kernel card,
and what OSV and the boxes say on a container card.

Advisories of one component that name the same fixed version are closed by one update, so they
share one card. An advisory with no fixed version gets its own. At most 6 new advisory, KEV and
kernel cards go out per run; the rest wait for the next run. The KEV feed is handled first, then
the kernel feed, so their pages never wait behind a component feed's quiet cards. A critical
advisory from a component's own feed takes its turn in the order of `watch.json`.

An advisory card is a notice: the watch never closes it, because nothing here can see whether you
installed the fix. Resolve it once you have handled it; an acknowledged one closes by itself after
`advisoryCards.closeAcknowledgedAfterDays` (90 days by default). It is sent once: a later change to
the advisory (a new severity, a new fixed version) does not edit it, and a resolved one does not
come back.

### The first read

The first read of a feed records everything in it, and cards only what was published in the last
30 days, so turning the watch on does not flood you. The KEV feed's first read cards nothing,
because every entry in the catalog would page. A component added to an existing setup is matched
against the KEV entries the catalog adds from then on.

### When a feed cannot be read

A feed that cannot be read (an error status, a timeout, a body that is not the feed, a redirect)
changes nothing: what was seen stays seen and nothing is closed. Once a feed has failed every read
for a day, one "Can't read ... advisories" card opens. It closes itself after the next good read.
It is not a clean bill of health while it is open. While the feed still fails, the card is sent
again every 6 hours with the new count of failed reads, so one resolved too early opens again.

Redirects are refused, so the GitHub token can never follow one to another host. A feed that moved
reads as failed until you put its new address in `watch.json`.

### Requests

Feeds are read with conditional requests when the server gives an ETag, so an unchanged feed
costs a `304`. The watch uses the hub's `GITHUB_TOKEN` when it is set (the lockfile scan uses the
same token), and sends it only to `https://api.github.com`. Without a token GitHub allows 60 API
requests an hour from one address, so set one if you list many GitHub feeds.

## The kernel feed

A box's own update check sees a kernel CVE only once Ubuntu ships the fix. A critical kernel bug
that can be reached over the network can sit unfixed for weeks before that, and nothing says so.
This feed says so while there is still no fix to install.

Each run it asks NVD for the Linux kernel records changed since the last run, and keeps those with
a CVSS 3 base score of 9.0 or more and a network attack vector. The score is the kernel CNA's own
when it gave one, else NVD's; Ubuntu's priority is not used, because Ubuntu often files a new kernel
CVE at a lower priority for days. Then it reads Ubuntu's record of each CVE for the `linux` package
on every release in `kernel.ubuntu`.

- A CVE that a release still has no released fix for (needed, pending, deferred, not triaged, no
  record yet) goes on a card. "Pending" means Ubuntu built the fix but has not released it as a
  security update, so it still counts as no fix.
- The CVEs one run finds share one card, which pings. The CVEs the feed's first read finds (the
  last 30 days) share one quiet card that grows as that read goes on.
- Ubuntu's record of the CVEs on open cards is read again each run, the longest unchecked first
  (see the cap below). A card closes itself once every listed release is fixed or not affected
  for all of its CVEs. From there, installing the fix is the normal update and reboot on each
  server.
- Until then, each open card is sent again every 6 hours with Ubuntu's latest status. The hub
  edits the card only when its text changed. A card a person resolved opens again as a new card,
  and the one that pinged pings again.

NVD, Ubuntu and a failed lookup follow the rules above: nothing moves until they answer, and a day
of failures opens one "Can't read Linux kernel advisories" card. A large window of NVD changes is
read over several runs, newest records first, 4 NVD requests a run (NVD allows 5 in 30 seconds
without an API key, and this sends no key). At most 40 new CVEs and 40 carded CVEs are looked up in
Ubuntu's records per run; the rest wait their turn.

## The container check

Each box's host detector sends one `container-packages` report per running container that
publishes a port or uses the host network (see the [report protocol](../report-protocol.md)). The
hub keeps the latest list per container. Every run, the check:

1. asks OSV which vulnerabilities affect each (distro release, source package, version);
2. reads each matched OSV record for its severity and fixed versions, from a cache in the hub's
   state (a record is read again when OSV says it changed, at most every 6 hours, or after a
   week), at most 250 records a run;
3. cards each image that has a CVE with a fix in its own distro release, rated critical or high.

### What gets a card

One quiet warning card per image. It never pings: the fix is a rebuild, which is daytime work, and
an OS package's score says little about whether the container ever runs the vulnerable code. The
card lists the package fixes the image needs (worst first, as many as fit), their CVEs, the boxes
and containers running the image, and when the image was built. It says when the tag moves
(`latest`, `16`, `2.8-alpine`), since pulling it again may already bring the fixes.

Severity is the CVSS v3 base score in the OSV record, or the distro's own rating when that is
higher (Debian urgency high, Ubuntu priority high or critical). A record with only a CVSS v4
vector, or no score, and no such distro rating counts as unknown and does not card.

Not carded, only counted in the run report's `fixable` field: medium, low, unknown severity, and
CVEs with no fix yet (`unfixed`). Debian's "unimportant" rating and a fix only Ubuntu Pro ships
count as no fix.

The card is edited in place when its fixes or containers change. A container on it is settled
once it was checked in full this run with the fix in, runs a different image, or is no longer
listed by the hub (its box reported it gone, or sent nothing for 30 days). A container whose box
has not reported for 3 days settles nothing and opens nothing.

All of that comes from what the boxes report, and a box cannot close an alert about itself (rule 4
in [the principles](../principles.md)). So the card never closes itself. Once every container on
it is settled, the card says what the boxes report (the fix, another image, the container gone),
is no longer sent again, and waits for a person to press Resolve. Check that the containers really
run the fix, then resolve it. If the image needs a fix again before anyone resolved the card, that
line goes and the card is edited and sent again as before; after it was resolved, a new card opens.

An open card that has not changed is sent again every 6 hours, at most 20 a run (the longest
unsent first, so with many cards some wait a little longer). The hub edits it only when its text
changed (the image's age, say). A card a person resolved while the image still needs the fix
opens again as a new card.

### When it cannot check

A run that cannot read the package lists or OSV changes nothing. After a day of such runs, one
"Can't check container packages" card opens, and it closes when a run gets through. Like the
advisory feed's card, it is sent again every 6 hours while it lasts. An OSV record that does not
read, with no cached copy to use, leaves its containers unchecked (they settle nothing) and is
fetched again next run.

## Resolving a watch card

Every watch card has Acknowledge and Resolve buttons (admins and the watcher role). Resolve closes
the card. What happens next depends on the card:

| Card | Closes by itself | After a person resolves it |
|---|---|---|
| KEV and advisory cards | Never, except an acknowledged one after `advisoryCards.closeAcknowledgedAfterDays` | It stays closed. |
| Kernel bug with no Ubuntu fix yet | Once every listed release has the fix | While the fix is still missing, it opens again within about 6 hours. |
| Container image | Never. Once the boxes report every listed container runs the fix, runs another image or is gone, it says so and waits for Resolve | While the image still needs the fix, it opens again within about 6 hours. A later gap in the image opens a new card. |
| Can't read advisories, can't check container packages | Once a read gets through | While reads still fail, it opens again within about 6 hours. |
| `watch.json` has a problem | On the next clean read | While the file is still wrong, it opens again on the next hourly run. |

A card that opens again is a new card under the same rules as the first one, so a critical
kernel card pings again. The cards themselves say this. Resolve a card when its problem is gone;
if you have handled it but the problem is still there (a mitigated kernel bug), Acknowledge it
instead.

The hub keeps at most 300 watch cards open, plus a reserve of 50 for critical ones. Past that, a new card is refused, the module tries it
again on its next run, and the status board shows "Watch cards are full" (`watch.refusedSince` in
[`/v1/state`](api.md)) until fewer than 300 are open.

## Run reports

Each `run()` returns a report (`AdvisoryRunReport` or `ContainerRunReport` in
`hub/src/watch/types.ts`) and never throws. A problem becomes a line in the hub's log (and goes in
the report's `errors`, or `failed` for a feed that could not be read). The counts in it
(`belowThreshold`, `skipped`, `fixable`, `unsupported`) say what was read but not carded, and
`resent` counts the open cards sent again on the 6-hour timer. The hub does not show these counts
anywhere yet; only the problems reach its log.

## Limits

- **Only what you list is watched.** A component that is not in `watch.json`, or whose feed is
  wrong, is not checked. The KEV feed matches only the `kev` names you give.
- **Feeds are what upstream publishes.** A project that announces fixes only in release notes, a
  mailing list or a web page has no feed here. GitHub feeds read published repository advisories
  only. RSS feeds must be RSS 2.0 (not Atom).
- **Advisory cards do not know what you installed.** They tell you a fix exists and where the
  software runs; comparing versions is yours.
- **The kernel feed covers Ubuntu's generic kernel only** (the `linux` source package). Other
  distributions, and Ubuntu's other kernel packages (HWE, cloud and other flavors), are not checked.
  It also depends on NVD and the kernel CNA scoring a record; a critical bug that is scored late is
  carded late.
- **The container check covers Debian, Ubuntu and Alpine images** with a package database
  (distroless Debian images count: the box reads their `status.d`). A container on another
  distribution, or an image with no package database (scratch, say), is listed in the report's
  `unsupported` and not checked. Language packages inside an image (npm, pip, Go modules) are not
  in the list a box sends, so they are not checked here. It is only as complete as OSV's data for
  those distributions.
- **What is tested:** the rules above are tested in `hub/test/watch/` against mocked feeds (small
  inline samples in the shapes of the real ones) with a pinned clock. Two limits have no test of
  their own: the 250 OSV records a run, and the kernel feed's place before the component feeds
  (only "KEV first" is tested). The rules for resolving a watch card, the "Watch cards are full"
  notice and `advisoryCards` are tested in
  `hub/test/watch/kernel.test.ts` and `hub/test/watch/containers.test.ts` (both also against the
  hub's own cards), `hub/test/watch-host.test.ts`, `hub/test/watch-jobs.test.ts` and
  `hub/test/handlers.test.ts`. RSS feeds built to be slow to parse, near the hub's 2 MiB cap on a
  feed, are tested to parse in under a second (`hub/test/watch/feeds.test.ts`), and feed, NVD,
  Ubuntu, OSV and box text that tries to hide a link is tested on each kind of card. No test
  reads a live feed, so a
  change in a feed's format would show up as a "can't read" card, not as a test failure.
