# The nethersec hub

The hub is a self-hosted Discord bot. It keeps the alert cards for everything nethersec watches:

- **Your servers and PCs.** The host scripts and the PC scanner send reports to the hub over
  HTTP ([the report protocol](../report-protocol.md)). Each problem gets one card that is edited
  in place, with Acknowledge, Mute and Resolve buttons.
- **Your GitHub repos.** It reads the lockfiles on each repo's default branch and posts a card
  when a dependency gets a new advisory. This is optional and needs a GitHub token.
- **Advisory feeds and containers.** The watch modules post their own cards through the hub,
  with Acknowledge and Resolve buttons (see [Watch cards](#watch-cards) and [watch.md](watch.md)).

It creates its own channels and a role to ping, keeps a status board, and posts a weekly summary
of the boxes that wait for a reboot. Scripts and agents can read its state over a small API
([api.md](api.md)) or through its MCP server ([mcp.md](mcp.md)).

This folder replaces discord-cve-monitor 1.x. An existing 1.x install keeps working; see
[Migrating from discord-cve-monitor 1.x](#migrating-from-discord-cve-monitor-1x).

## Contents

- [Setup](#setup)
- [Channels and cards](#channels-and-cards)
- [Commands](#commands)
- [Report keys](#report-keys)
- [Reaching the hub from servers and PCs](#reaching-the-hub-from-servers-and-pcs)
- [Configuration](#configuration)
- [Repo scanning](#repo-scanning)
- [Limits](#limits)
- [Migrating from discord-cve-monitor 1.x](#migrating-from-discord-cve-monitor-1x)
- [Privacy and security](#privacy-and-security)
- [What is tested](#what-is-tested)
- [Development](#development)

## Setup

You need a machine that stays on (a small VPS, a home server, a Raspberry Pi), and either
Node.js 22.9 or newer, or Docker. Run the commands below in the `hub/` folder.

### 1. Create the Discord bot

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) and click
   **New Application**.
2. On the **Bot** page, click **Reset Token** and copy the token. This is your `DISCORD_TOKEN`.
3. Still on the **Bot** page, turn off **Public Bot** so only you can add it to a server. No
   privileged intents are needed.
4. Copy the **Application ID** from the **General Information** page. You need it for the invite
   link below.

### 2. Create a GitHub token (optional)

Skip this if you do not want repo scanning. The hub only reads. Pick one:

- **Fine-grained token** (recommended): GitHub > Settings > Developer settings > Fine-grained
  tokens. Choose the repos (or all repos) of one owner, and give it **Contents: Read-only**.
  Fine-grained tokens cannot reach repos owned by someone else where you are only a collaborator.
- **Classic token** with the `repo` scope: covers every repo you can read, including repos you
  collaborate on and repos in your organizations. It can also write, so keep it safe. With no
  scope at all, a classic token only sees public repos.

If an organization uses SAML single sign-on, authorize the token for it, or its repos stay hidden
(the status board tells you when this happens).

### 3. Configure

```bash
cp .env.example .env
```

Fill in `DISCORD_TOKEN` and `DISCORD_GUILD_ID` (right-click your server icon > Copy Server ID,
with Developer Mode on in Discord's Advanced settings). Add `GITHUB_TOKEN` for repo scanning.
The other settings are in [Configuration](#configuration).

### 4. Run it

With Docker:

```bash
docker compose up -d --build
```

The compose file names the service `hub` and the image `nethersec-hub`, keeps the data in the
`hub-data` volume, and publishes the report server on `127.0.0.1:8787` only. It gives the hub 60
seconds to stop, so a running scan can finish. With plain `docker run`, pass `--stop-timeout 60`
for the same.

Or with Node.js:

```bash
npm ci
npm run build
npm start
```

If the hub cannot log in to Discord when it starts (a wrong token, or no network), it logs why
and exits. Docker's restart policy starts it again.

### 5. Invite it and run setup

If the bot is not in your server yet, it prints an invite link when it starts. You can also build
it yourself, with your Application ID:

```
https://discord.com/oauth2/authorize?client_id=YOUR_APPLICATION_ID&scope=bot+applications.commands&permissions=378225642576
```

The permissions are View Channels, Send Messages, Embed Links and Read Message History for
posting, plus Manage Channels, Manage Roles, Create Public Threads, Create Private Threads, Send
Messages in Threads and Add Reactions for `/nethersec setup`. Discord only lets a bot set a
channel permission it has itself, so setup needs the thread and reaction permissions to turn them
off in the alert channels. The bot never starts threads or reacts.

Then, in your server, run:

```
/nethersec setup
```

It creates a **nethersec** category with three read-only channels and a **nethersec watch** role
(see [Channels and cards](#channels-and-cards)). The channels are private by default: only admins
and members with the role can see them. Run `/nethersec setup private:False` to let everyone in
the server read them. Only the bot and server administrators can post in them; members with the
role can open a thread on an alert and react, to talk it over. The role is mentionable, so the bot
can ping it without extra permissions. Running setup again recreates anything that was deleted.

With a GitHub token, the first repo scan starts right away. By default the hub watches every repo
the token can read, without forks and archived repos.

### 6. Make a key for each box

See [Report keys](#report-keys), then [Reaching the hub from servers and PCs](#reaching-the-hub-from-servers-and-pcs).

## Channels and cards

| Channel | What goes there |
| --- | --- |
| `#nethersec-critical` | Critical cards: repo advisories rated critical, malware, critical host reports and watch cards. A card that rises to critical gets a short note here too. |
| `#nethersec-alerts` | Other cards: repo advisories at your alert level (High and above by default), host warnings, watch warnings. |
| `#nethersec-status` | The status board, info notes from hosts, info watch cards, the weekly pending-reboot summary, newly watched repos, fixes and problems. |

### Host cards

A report's identity is its kind, source and event (`security:web1:ssh-auth-burst`). The hub keeps at
most one open card per identity:

- **A new problem** gets a card: `critical` in the critical channel, `warning` in the alerts
  channel. An `info` report with no open card is a note in the status channel, not a card. The
  same note from the same check (same title, detail and group) is posted at most once an hour.
- **The same problem again** edits the card in place. An unchanged report edits nothing.
- **Pings.** A new critical card pings the **nethersec watch** role only when the source's key has
  the `page` flag. A card that rises to critical later gets a note in the critical channel, which
  pings under the same rule. Nothing else pings. `/nethersec settings ping_critical:False` turns
  every ping off.
- **A security report that says `resolved`** adds "The box reports this is fixed" to the card. The
  card stays open until a person presses **Resolve**. A box cannot close its own security alert,
  so a box that was taken over cannot quietly clear the alert about it.
- **An uptime report that says `resolved`** closes the card ("Back up").
- **A source with a `dm=` key** gets no card at all: each report is one direct message to that
  person, and nothing goes to a channel. If the message cannot be delivered (the person does not
  share the server with the bot, or does not accept direct messages from it), the report is
  answered 503 and the PC sends it again on its next run.

What a box sends (title, detail, group) is shown as plain text. It cannot format the card, add a
link, or mention a role or a user.

The buttons on a host card:

| Button | Who | What it does |
| --- | --- | --- |
| Acknowledge | admins and the watcher role | Records who is handling it. |
| Mute | admins (Manage Server) | No new card and no ping for this check from now on. The open card is still edited. Undo with `/nethersec host-unmute`. |
| Resolve | admins and the watcher role | Closes the card. A later report for the same check opens a new one. |

### Watch cards

The advisory watch and the container check ([watch.md](watch.md)) post watch cards. They go
where their severity goes, like host cards, and have two buttons:

| Button | Who | What it does |
| --- | --- | --- |
| Acknowledge | admins and the watcher role | Records who is handling it. |
| Resolve | admins and the watcher role | Closes the card. |

There is no Mute: a watch card is not one check on one box. Some watch cards close by
themselves, and some only close when a person resolves them:

| Card | Closes by itself | Resolve |
| --- | --- | --- |
| Exploited in the wild (KEV) and advisory cards | No. These are notices: nothing here can see whether you installed the fix. | Resolve it once every place is handled. It does not come back. One that was acknowledged closes by itself 90 days after that by default (`advisoryCards` in `watch.json`). |
| Kernel bug with no Ubuntu fix yet | Yes, once every listed Ubuntu release has the fix. | While the fix is still missing, it opens again within about 6 hours, and a critical one pings again. |
| Container image | No. Once the boxes report that every listed container runs the fix, runs another image or is gone, the card says so and is not sent again. A box's word cannot close it. | Resolve it once you have checked. While the image still needs the fix, it opens again within about 6 hours. |
| Can't read advisories, can't check container packages | Yes, once a read gets through. | While reads still fail, it opens again within about 6 hours. |
| `watch.json` has a problem | Yes, on the next clean read. | While the file is still wrong, it opens again on the next hourly run. |

So Resolve on a problem that is still there is temporary. If you have handled it but the fix is
not out yet (you mitigated a kernel bug, say), press Acknowledge and leave it open. Container cards
the boxes report fixed stay open until someone resolves them, so the status board counts them
("reported fixed and waits for Resolve") and `/nethersec alerts kind:watch` marks each one.

At most 300 watch cards are open at a time (a critical one may still open while fewer than 350 are). Past that, a new one is refused: the status board
shows "Watch cards are full" with when it started, `/v1/state` sets `watch.refusedSince`, and the
module tries the card again on its next hourly run. Resolve the cards you have handled to make
room; the notice goes as soon as there is room.

### Repo advisory cards

One card per advisory per scan, listing each repo it is new in, with the installed version and
the version that fixes it. **Acknowledge** (admins and the watcher role) records who is handling
it, and **Mute advisory** (admins) stops alerts for that advisory in every repo. The rules that
keep it quiet are in [Repo scanning](#repo-scanning).

### The weekly pending-reboot summary

Hosts send their pending reboot as data (the `reboot-pending` event), not as an alert. On Mondays
from 09:00 UTC the hub posts one summary to the status channel: each box with a reboot pending,
how long it has waited, whether High or Critical fixes wait for the reboot, and whether the data
is stale (no report for over 2 days). It posts at most once a week, and nothing in a week with no
pending reboot. A box with no report for 30 days drops off the list. `/nethersec reboots` shows
the same list any time.

## Commands

All commands are admin-only (Manage Server) by default. A server admin can open them to other
roles under Server Settings > Integrations.

| Command | What it does |
| --- | --- |
| `/nethersec setup` | Create or repair the channels and the role. |
| `/nethersec status` | The status board, just for you. |
| `/nethersec hosts` | Every source that has reported, when it last did, and how many alerts it has open. |
| `/nethersec alerts [kind] [source]` | Open host and watch alerts, with links to their cards. |
| `/nethersec reboots` | Boxes with a reboot pending. |
| `/nethersec keys` | Which sources have a report key and what their flags are. No key or hash is shown. |
| `/nethersec host-unmute <source> <check> [kind]` | Turn a muted host check back on. |
| `/nethersec scan` | Scan the repos now. |
| `/nethersec findings [repo] [severity]` | List open repo advisories. |
| `/nethersec repos list` | Show how repos are chosen and which are watched. |
| `/nethersec repos add <repo>` | Watch a repo (also one the token's list does not include, like someone else's public repo). |
| `/nethersec repos remove <repo>` | Stop watching a repo. |
| `/nethersec repos mode <mode>` | Watch every repo the token can read, or only the ones you add. |
| `/nethersec settings` | Alert level, pings, forks, archived repos and scan interval. |
| `/nethersec mute <advisory> [repo]` | Stop alerts for an advisory (its GHSA or CVE ID), everywhere or in one repo. |
| `/nethersec unmute <advisory> [repo]` | Turn them back on. |
| `/nethersec mutes` | List muted advisories and host checks. |
| `/nethersec pause` / `/nethersec resume` | Stop and restart repo scanning. |

## Report keys

Every box (or PC) that reports has its own key, bound to one source name. The hub stores only the
SHA-256 of each key, in `DATA_DIR/keys.txt`:

```
# <source> <sha256 of the key> [page | dm=<Discord user ID>]
web1 <64 hex characters> page
db1  <64 hex characters>
pc1  <64 hex characters> dm=<your Discord user ID>
```

- `page`: a critical report from this source pings the watcher role. Give it to servers, not to
  devices that can be carried off.
- `dm=<Discord user ID>`: reports from this source go only to that person, by direct message. For
  a personal PC. A `dm=` key cannot send the data events.
- A line with both flags, a bad hash, an unknown flag or a key listed twice is refused, and the
  hub logs its line number (never the hash or the user ID).
- `#` starts a comment. When a report comes in, the hub looks at the file (at most once a
  second) and reloads it if it changed, so a new or revoked key works without a restart.

Manage the file with the hub's CLI. With Docker, run it in the container:

```bash
docker compose exec hub node dist/cli.js key new web1 --page
```

With Node.js, run `npm run --silent key -- ...` in the `hub/` folder; like `npm start`, it reads
`DATA_DIR` from `.env`. Plain `node dist/cli.js key ...` reads `DATA_DIR` from the environment only.

| Command | What it does |
| --- | --- |
| `key new <source> [--page \| --dm <user ID>]` | Makes a key, prints it once on stdout (nothing else goes there), and stores its hash. |
| `key add <source> <sha256> [--page \| --dm <user ID>]` | Stores the hash of a key made on the box, so the key never leaves it. |
| `key list` | Sources, flags and the first 12 characters of each hash. |
| `key revoke <source> [<hash prefix>]` | Removes every key of a source, or only the one whose hash starts with the prefix. |

To make the key on the box instead, hash it there and give the hub only the hash (`printf` is a
shell builtin, so the key is not on a command line):

```sh
printf %s "$KEY" | sha256sum
```

To replace a key without a gap, add the new one, move the box to it, then revoke the old one by
its hash prefix (`key list` shows it).

On the box, keep the key in a file only its owner can read (mode 600), and pass it to `curl` on
stdin, never as an argument. The host scripts do this for you; see their docs.

## Reaching the hub from servers and PCs

The report server speaks plain HTTP on `NETHERSEC_LISTEN` (default `127.0.0.1:8787`; the compose
file publishes it on the host's loopback only). A key sent over plain HTTP on the open internet
can be read on the way, so pick one:

**A reverse proxy with HTTPS.** Put a proxy in front and pass on only the report and health
paths. With [Caddy](https://caddyserver.com), which gets a certificate by itself:

```
hub.example.com {
	@reports path /v1/report /v1/health
	handle @reports {
		reverse_proxy 127.0.0.1:8787
	}
	handle {
		respond 404
	}
}
```

Then set `NETHERSEC_PUBLIC_URL=https://hub.example.com`. Keep `/v1/state` off the public side
unless you need it there; it has its own token either way. This is an example, not something the
tests run.

**A private network.** Over a VPN or a tailnet the boxes can reach the hub on its private
address. In `docker-compose.yml`, publish the port on that address instead of loopback, like
`- "<private address>:8787:8787"`, and set `NETHERSEC_PUBLIC_URL=http://<private address>:8787`.

Behind a proxy, every report arrives from the proxy's address. The rate limits are per source and
in total, never per address, so this changes nothing.

## Configuration

| Variable | Required | What it is |
| --- | --- | --- |
| `DISCORD_TOKEN` | yes | The bot token. |
| `DISCORD_GUILD_ID` | yes | The one server the bot serves. It leaves any other server. |
| `GITHUB_TOKEN` | no | A token that can read your repos. Without it, repo scanning is off and the status board says so. |
| `NETHERSEC_LISTEN` | no | Where the report server listens, as `host:port` or `[v6 address]:port` (default `127.0.0.1:8787`; the Docker image sets `0.0.0.0:8787`). |
| `NETHERSEC_API_TOKEN` | no | Turns on `GET /v1/state` with this bearer token, at least 24 characters (`openssl rand -hex 32`). Unset, the state API is off. |
| `NETHERSEC_PUBLIC_URL` | no | The URL boxes use to reach the hub, shown in setup hints and on the status board. |
| `SCAN_INTERVAL_MINUTES` | no | Minutes between repo scans for a new install, 15 to 1440 (default 60). Change it later with `/nethersec settings`. |
| `DATA_DIR` | no | Where the state file and `keys.txt` live (default `./data`, `/data` in Docker). |

The report keys are in `DATA_DIR/keys.txt` and the watch settings in `DATA_DIR/watch.json`
([watch.md](watch.md)). Everything else is set from Discord and saved in `DATA_DIR/state.json`.
Back that folder up if you care about your settings and open cards; the previous copy is kept as
`state.json.bak`.

## Repo scanning

With a GitHub token, the hub reads the lockfiles on each watched repo's default branch.

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3) |
| pnpm | `pnpm-lock.yaml` (v5, v6, v9) |
| Yarn | `yarn.lock` (classic and Berry) |
| Bun | `bun.lock` (the text format) |
| Python | `requirements*.txt` and `requirements/*.txt` (exact `==` pins), `uv.lock`, `poetry.lock` |

Not supported yet: `bun.lockb`, `Pipfile.lock` and `pdm.lock` are listed as skipped, never treated
as clean. Lockfiles of other ecosystems (Go, Rust, Java, Ruby...) are not read and not listed. In a
`requirements.txt`, a line that is not an exact pin (`flask>=2`) cannot be checked, so pin your
full dependency set (`pip freeze`) to get coverage.

Every installed package with a registry version is checked against the GitHub advisory database
(through npm's advisory endpoint) and [OSV](https://osv.dev) for Python. It reads lockfiles
directly, so it works on any repo the token can read, including repos where you are only a
collaborator.

It is built to stay quiet:

- **No flood on day one.** The first scan of a repo records what is already open and posts one
  summary. Only advisories that appear after that get their own card. Malware is the exception: it
  gets its own card even on the first scan.
- **One card per advisory per scan.** The same advisory new in 12 repos in one scan is one card and
  at most one ping.
- **At most 10 cards per scan.** Anything past that is listed in one summary message, never dropped.
- **No false all-clear.** Nothing is marked fixed unless it was checked:
  - A repo that cannot be read keeps what was open there, and is reported after two scans in a row.
  - A lockfile that is too big or cannot be parsed, or a repo too big to list in full, keeps what
    was open in it.
  - If an advisory source is down, nothing in that ecosystem is marked fixed until it is back. If
    it was down during a repo's first scan, the next scan records that backlog quietly instead of
    alerting on all of it.
- **Repos that come back still alert.** A repo that drops off the watch list is remembered for 30
  days, so if it returns, its new advisories get cards instead of being recorded quietly again.
- **Mutes** by advisory ID or by CVE. Dev-only findings do not ping unless you ask.
- **Safe restarts.** On shutdown the hub waits up to 45 seconds for a running scan to finish
  posting and saving, so a restart does not post the same cards twice.

A scan costs about one GitHub request per repo, plus one per changed lockfile, one per 100 repos
for the repo list, and up to 40 lookups for fix versions. Repos whose default branch has not moved
since the last scan answer from cache and do not count against GitHub's rate limit. The cache is
kept in memory, so the first scan after a restart reads every repo again. If the limit runs low,
the remaining repos wait for the next scan and keep what they had. The repo list is read up to
2000 repos; past that, the status board says so, and `/nethersec repos mode` "Only repos I add"
lets you pick.

## Limits

Reports are rate limited per source and in total (see the [protocol](../report-protocol.md#what-the-hub-does-with-a-report)):
25 alert reports a minute per source and 100 in total, the data events 30 a minute per source and
150 in total, and a `dm=` source 15 reports an hour. Over a limit, the answer is 429 with a
`Retry-After`. A refused report counts toward none of the limits, so one source cannot use up
the total by itself. When the total refuses a source that is under its own limit, the hub logs it
(at most once a minute, with the sources that sent the most that minute) and the status board shows
"Reports refused" until a report gets through an hour or more after the last such refusal. A source that sends far more than its
box should may have a stolen key: revoke it with `node dist/cli.js key revoke <source>`.

Every collection a key holder can add to has a cap, so it cannot grow without end:

| What | Cap | Past it |
| --- | --- | --- |
| Open host cards | 300 in all, 30 per source | A new one is answered 429 until some are resolved. The source's open cards are still edited. |
| Info notes remembered, so the same one is not posted twice in an hour | 500, in memory | The oldest are forgotten first. A restart forgets them all. |
| Open watch cards | 300, plus 50 for critical cards | A new watch card is refused and tried again on the module's next run. The status board shows "Watch cards are full" (and `/v1/state` sets `watch.refusedSince`) until fewer than 300 are open. |
| Host and watch cards kept, open and closed | 1,000 | The oldest closed cards are forgotten first. A closed card is forgotten after 30 days anyway; its message stays in Discord. |
| Muted host checks | 200 | A new mute is refused. |
| Container package lists | 200 in all, 50 per source | A new container is answered 429; known ones still update. |
| Packages per container | 800 | The rest are counted in `more`. |
| Pending reboots | 200 sources | A new source is answered 429. |
| Sources in the host list | 500 | Reports still work; the new source is not listed. |
| Watch module state | 512 kB per module, 256 modules, 16 MB in all | The save is refused. |

## Migrating from discord-cve-monitor 1.x

The hub reads a 1.x data folder as it is. Your settings, watched repos, open findings, cards,
mutes, channels and role are kept, and the cards already posted keep working buttons. The state
file is rewritten as version 2 on the next save.

1. Stop the old bot, and copy its data folder somewhere safe. Going back to 1.x after the upgrade
   is not tested.
2. Keep your `.env`. `DISCORD_TOKEN`, `DISCORD_GUILD_ID` and `GITHUB_TOKEN` mean the same. Add the
   new settings from `.env.example` if you want them.
3. **With Node.js:** point `DATA_DIR` at the 1.x data folder (the 1.x default was `./data` in the
   folder it ran from, not in `hub/`) and start the hub.
   **With Docker:** the 1.x compose file kept the data in a volume named after its project, like
   `discord-cve-monitor_cve-data` (`docker volume ls` shows it). Point the new compose file at it
   with a `docker-compose.override.yml` next to it:

   ```yaml
   services:
     hub:
       volumes:
         - old-data:/data
   volumes:
     old-data:
       external: true
       name: discord-cve-monitor_cve-data
   ```

   Then `docker compose up -d --build`.
4. In Discord, the `/cve` command is replaced by `/nethersec` the first time the hub starts. The
   channels keep their names (`#cve-critical` and so on) and the role stays **CVE Watch**: setup
   finds them by ID, so you can rename them by hand if you like. `/nethersec setup` is not needed.

## Privacy and security

- From your repos, the hub downloads the file list and the lockfiles only, never your source code.
- The GitHub token is sent only to `api.github.com`, on read requests. It is never logged or posted.
- For repo scanning, the names and versions of your dependencies (not your repo names) are sent
  to `registry.npmjs.org` and `api.osv.dev`. If that is not acceptable for your project, leave
  `GITHUB_TOKEN` unset. The container check, on by default, sends the OS package names and
  versions your servers report for their containers to `api.osv.dev` ([watch.md](watch.md)).
- Report keys are stored as SHA-256 hashes, compared in constant time. A key can only send reports
  for its own source. The hub never echoes a key, a title or a detail back in its answers.
- `keys.txt` and `state.json` are written readable by their owner only.
- Alerts reveal which of your repos and boxes are vulnerable to what. Keep the channels private
  unless the whole server should see them.

See [SECURITY.md](../../SECURITY.md) to report a problem.

## What is tested

The tests run in CI on Node 22 and 24 (`npm test`, with `npm run typecheck` and `npm run build`),
and CI builds the Docker image. They cover:

- the report body rules, field by field (`test/protocol.test.ts`);
- the keys file, its reload, refused lines by number, bearer matching, and the key CLI (`test/keys.test.ts`);
- the card lifecycle against a fake Discord: routing by severity, pings with and without `page`,
  edits in place, the rise to critical, a resolved security card waiting for Resolve, an uptime
  card closing, mutes, the open host card caps (in all and per source), info notes posted once an
  hour, mention safety, the DM path, a 503 that keeps no card, rate limits (a source over its own
  limit cannot use up the total; a refusal at the total is logged and shown on the status board),
  and the data events with the per-source container cap and the package cap
  (`test/reports.test.ts`);
- the HTTP server: every status code but 500, 413, `Retry-After`, and the state API's token (`test/server.test.ts`);
- the host and watch card buttons, including Resolve on a watch card (`test/handlers.test.ts`), the watch
  module surface and hourly jobs (`test/watch-host.test.ts`, `test/watch-jobs.test.ts`): a
  resolved watch card that opens again on the next upsert, a watch card marked reported fixed
  that stays open for Resolve, the "Watch cards are full" notice on the status board and in the
  state view, and acknowledged advisory cards closing after
  `advisoryCards.closeAcknowledgedAfterDays` with a pinned clock; the weekly summary with a pinned
  clock (`test/digest.test.ts`), the MCP server (`test/mcp.test.ts`), and loading a 1.x data
  folder plus setup reusing its channels (`test/migration.test.ts`);
- the 1.x repo scanner: lockfile parsing, advisory matching, fix versions and the alert rules.

Not tested: **the Discord login has never been run live.** Cards, buttons and direct messages are
tested with a fake Discord, so a difference between the fake and the real Discord API would not
show in the tests. GitHub, npm and OSV are tested with fakes too. The reverse proxy example and the
compose file are not run by the tests, and CI builds the image without running it.

## Development

```bash
npm ci
npm run typecheck
npm test
```

Test inputs are written inline on purpose: a test file named like a real lockfile would get picked
up by GitHub's dependency graph, and by the hub. Test keys are made at runtime, never written as
literals.
