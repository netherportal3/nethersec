# Discord CVE Monitor

A self-hosted Discord bot that watches your GitHub repos for dependencies with known
vulnerabilities, and posts an alert when a new one shows up. It creates its own channels and a
role to ping, keeps a live status board, and tells you which version fixes each problem.

It reads your lockfiles directly, so it works on any repo your GitHub token can read, including
repos where you are only a collaborator and cannot turn on Dependabot.

## What it does

- Reads the lockfiles on each repo's default branch: npm, pnpm, Yarn, Bun, pip, uv and Poetry.
- Checks every installed package against the GitHub advisory database (through npm's advisory
  endpoint) and [OSV](https://osv.dev) for Python.
- Posts one alert card per new advisory, listing every affected repo, the installed version and
  the version that fixes it. Critical advisories and malware ping a role.
- Marks a card as fixed once the advisory is gone from every repo, and says so in the status
  channel.
- Keeps a status board up to date after every scan: what is open, what could not be read, and
  when the next scan runs.

### Built to stay quiet

- **No flood on day one.** The first scan of a repo records what is already open and posts one
  summary. Only advisories that appear after that get their own alert.
- **One card per advisory.** The same advisory in 12 repos is one card and at most one ping.
- **At most 10 cards per scan.** Anything past that is listed in one summary message, never dropped.
- **No false all-clear.** A repo that cannot be read keeps what was open there and is reported
  after two scans in a row. If an advisory source is down, nothing is marked fixed until it is back.
- **Acknowledge and mute** buttons on every card, and dev-only findings do not ping unless you ask.

## Supported lockfiles

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3) |
| pnpm | `pnpm-lock.yaml` (v5, v6, v9) |
| Yarn | `yarn.lock` (classic and Berry) |
| Bun | `bun.lock` (the text format) |
| Python | `requirements*.txt` and `requirements/*.txt` (exact `==` pins), `uv.lock`, `poetry.lock` |

Not supported yet: `bun.lockb`, `Pipfile.lock`, `pdm.lock`, and other ecosystems (Go, Rust, Java,
Ruby...). Unsupported lockfiles are listed as skipped, never treated as clean. In a
`requirements.txt`, a line that is not an exact pin (`flask>=2`) cannot be checked, so pin your
full dependency set (`pip freeze`) to get coverage.

## Setup

You need a machine that stays on (a small VPS, a home server, a Raspberry Pi), and either
Node.js 22.9 or newer, or Docker.

### 1. Create the Discord bot

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) and click
   **New Application**.
2. On the **Bot** page, click **Reset Token** and copy the token. This is your `DISCORD_TOKEN`.
3. Still on the **Bot** page, turn off **Public Bot** so only you can add it to a server. No
   privileged intents are needed.
4. Copy the **Application ID** from the **General Information** page. You need it for the invite
   link below.

### 2. Create a GitHub token

The bot only reads. Pick one:

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

Fill in `DISCORD_TOKEN`, `DISCORD_GUILD_ID` (right-click your server icon > Copy Server ID, with
Developer Mode on in Discord's Advanced settings) and `GITHUB_TOKEN`.

### 4. Run it

With Docker:

```bash
docker compose up -d --build
```

Or with Node.js:

```bash
npm ci
npm run build
npm start
```

### 5. Invite it and run setup

If the bot is not in your server yet, it prints an invite link when it starts. You can also build
it yourself, with your Application ID:

```
https://discord.com/oauth2/authorize?client_id=YOUR_APPLICATION_ID&scope=bot+applications.commands&permissions=268520464
```

The permissions are View Channels, Send Messages, Embed Links, Read Message History, Manage
Channels and Manage Roles. The last two are only used by `/cve setup`.

Then, in your server, run:

```
/cve setup
```

It creates a **CVE Monitor** category with three read-only channels and a **CVE Watch** role:

| Channel | What goes there |
| --- | --- |
| `#cve-critical` | Critical advisories and malware. Pings the CVE Watch role. |
| `#cve-alerts` | Other new advisories at your alert level (High and above by default). |
| `#cve-status` | The status board, newly watched repos, fixes and problems. |

The channels are private by default: only admins and members with the **CVE Watch** role can see
them. Run `/cve setup private:False` to let everyone in the server read them. Running setup again
recreates anything that was deleted.

The first scan starts right away. By default the bot watches every repo the token can read,
without forks and archived repos.

## Commands

All commands are admin-only (Manage Server) by default. A server admin can open them to other
roles under Server Settings > Integrations.

| Command | What it does |
| --- | --- |
| `/cve setup` | Create or repair the channels and the role. |
| `/cve status` | The status board, just for you. |
| `/cve scan` | Scan now. |
| `/cve findings [repo] [severity]` | List what is open. |
| `/cve repos list` | Show how repos are chosen and which are watched. |
| `/cve repos add <repo>` | Watch a repo (also one the token's list does not include, like someone else's public repo). |
| `/cve repos remove <repo>` | Stop watching a repo. |
| `/cve repos mode <mode>` | Watch every repo the token can read, or only the ones you add. |
| `/cve settings` | Alert level, pings, forks, archived repos and scan interval. |
| `/cve mute <advisory> [repo]` | Stop alerts for an advisory, everywhere or in one repo. |
| `/cve unmute <advisory> [repo]` | Turn them back on. |
| `/cve mutes` | List muted advisories. |
| `/cve pause` / `/cve resume` | Stop and restart scanning. |

On an alert card, **Acknowledge** (admins and the CVE Watch role) records who is handling it, and
**Mute advisory** (admins) stops alerts for that advisory in every repo.

## Configuration

| Variable | Required | What it is |
| --- | --- | --- |
| `DISCORD_TOKEN` | yes | The bot token. |
| `DISCORD_GUILD_ID` | yes | The one server the bot serves. It leaves any other server. |
| `GITHUB_TOKEN` | yes | A token that can read your repos. |
| `SCAN_INTERVAL_MINUTES` | no | Minutes between scans for a new install, 15 to 1440 (default 60). Change it later with `/cve settings`. |
| `DATA_DIR` | no | Where the state file lives (default `./data`, `/data` in Docker). |

Everything else is set from Discord and saved in `DATA_DIR/state.json`. Back that folder up if you
care about your settings; the previous copy is kept as `state.json.bak`.

## Privacy and security

- The bot downloads lockfiles only, never your source code.
- The GitHub token is sent only to `api.github.com`, on read requests. It is never logged or posted.
- To look up advisories, the names and versions of your dependencies (not your repo names) are sent
  to `registry.npmjs.org` and `api.osv.dev`. If that is not acceptable for your project, do not run it.
- Alerts reveal which of your repos are vulnerable to what. Keep the channels private unless the
  whole server should see them.

See [SECURITY.md](SECURITY.md) to report a problem.

## Rate limits

A scan costs about one GitHub request per repo, plus one per changed lockfile. Repos whose default
branch has not moved since the last scan answer from cache and do not count against GitHub's rate
limit. If the limit runs low, the remaining repos wait for the next scan and keep what they had.

## Development

```bash
npm ci
npm run typecheck
npm test
```

Lockfile parsing, advisory matching, fix versions and the alert rules are pure functions with
tests in `test/`. Test inputs are written inline on purpose: a test file named like a real
lockfile would get picked up by GitHub's dependency graph, and by this bot.

## License

MIT. See [LICENSE](LICENSE).
