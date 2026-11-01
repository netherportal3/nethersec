# nethersec

[![hub](https://github.com/netherportal3/nethersec/actions/workflows/hub.yml/badge.svg)](https://github.com/netherportal3/nethersec/actions/workflows/hub.yml)
[![Host scripts](https://github.com/netherportal3/nethersec/actions/workflows/host.yml/badge.svg)](https://github.com/netherportal3/nethersec/actions/workflows/host.yml)
[![PC scanner](https://github.com/netherportal3/nethersec/actions/workflows/pc.yml/badge.svg)](https://github.com/netherportal3/nethersec/actions/workflows/pc.yml)

Self-hosted security monitoring for a few Linux servers, a Windows PC and your GitHub repos. It
alerts you in Discord when something needs you and stays quiet the rest of the time.

It is built for one person or a small team looking after a handful of machines. It ships with
agent skills, so a coding agent can set it up and help you act on what it finds.

> **0.1.0 is the first release.** So far it has run only in tests, CI and a test install in a
> container. Each part's doc says what is tested and what is not.

## What it watches

| Where | What you hear about |
|---|---|
| GitHub repos | A dependency that gets a known vulnerability or turns out to be malware. It reads npm, pnpm, Yarn, Bun, pip, uv and Poetry lockfiles. |
| Ubuntu servers | High or Critical security fixes stuck uninstalled, reboots a fix is waiting on, SSH accepting passwords, unexpected open ports, Livepatch off, bursts of SSH login attempts or log errors. |
| Containers | Fixable critical or high CVEs in the OS packages of running images. |
| Upstream | New advisories and CISA known-exploited entries for software you list, and critical network-reachable kernel bugs Ubuntu has not fixed yet. |
| Windows PC | Missing security updates, Defender or the firewall off, apps that are behind or end of life, outdated Node, Go or Java, WSL distros behind on updates, known-exploited bugs in installed software. |
| Server traffic | Connection, packet, HTTP and SMTP floods. |

## What it changes

Out of the box it only watches. Three parts can change a machine, and each starts off or in
dry-run:

- The [update applier](docs/host/applier.md) installs ordinary Ubuntu updates once they are a few
  days old, so a bad release has time to be pulled first. Security updates stay on Ubuntu's own
  fast path. In dry-run it already holds updates back while they age, but installs nothing.
- [Flood blocking](docs/host/flood.md) drops the main source of a flood for a while. In dry-run it
  only names the address it would drop.
- The [mitigation scripts](docs/host/mitigations.md) block a kernel bug's trigger before a fix
  exists. They do nothing until you run one.

Adding the applier also installs `python3-apt` if it is missing, runs the applier just before
unattended-upgrades, and turns on Docker live-restore where Docker is installed.

## How it behaves

- A check that cannot read something says so. It never reports "fixed" after a failed read.
- You hear about a problem when it starts and when it ends, with a slow reminder in between.
- It pages only when a person is needed now. Routine patching pages nobody.
- A server can say a problem looks fixed, but only a person closes the alert.
- Anything that can change a machine ships switched off.

The reasoning is in [docs/principles.md](docs/principles.md).

## How the parts connect

```
servers      host/ scripts ──┐
Windows PC   pc/ scanner   ──┼── POST /v1/report ──>  hub/ ──> Discord channels and DMs
your scripts               ──┘   (one key per box)     │
                                                       ├── scans GitHub lockfiles
                                                       ├── reads advisory feeds and OSV
agents ── skills/ ── MCP server or GET /v1/state ──────┘   (read-only, own token)
```

The hub is one Node process that keeps its state in a JSON file. Servers and the PC send it small
reports over the [report protocol](docs/report-protocol.md). Each key belongs to one machine, and
the hub stores only its hash. You can run the server scripts without a hub, posting to a Discord
webhook, ntfy or any JSON endpoint, but then you get no alert cards, no Resolve button and no
reboot or container data.

## Set it up

1. Run the hub: a Discord bot you create, started with Docker Compose. See [docs/hub](docs/hub/README.md).
2. Add a server: clone this repo on it and run `host/install.sh`. See [docs/host](docs/host/README.md).
3. Add your Windows PC with `pc/install.ps1`. See [docs/pc](docs/pc/README.md).
4. List the software you run in `watch.json`, so the hub watches its advisories. See
   [docs/hub/watch.md](docs/hub/watch.md).

## Set it up with an agent

The [skills](skills/) cover setup, adding a server or PC, triaging an alert, responding to a new
advisory, fixing one vulnerable dependency across many repos, and switching on the parts that
change things. They ask before reboots, firewall or SSH changes, and before switching anything on.

In Claude Code:

```
/plugin marketplace add netherportal3/nethersec
/plugin install nethersec@nethersec
```

Then ask it to set up nethersec. Other agents that read [Agent Skills](https://agentskills.io) can
use the `skills/` folder from a clone of this repo.

nethersec is not a library, and nothing gets added to your codebase. Adding it to a project means
running the hub, installing the scripts on your machines and giving your agents the skills. To give
the skills to everyone who works in a repo, run this once in it and commit the
`.claude/settings.json` it writes:

```
claude plugin marketplace add netherportal3/nethersec --scope project
claude plugin install nethersec@nethersec --scope project
```

Agents can also read the hub's state through a read-only [MCP server](docs/hub/mcp.md) or
[`GET /v1/state`](docs/hub/api.md), each with its own token, and check a server with
`host/nethersec-status.sh --json`.

## Requirements

- Hub: Docker or Node 22.9+, and a Discord server you can add a bot to. A GitHub token only if you
  want repo scanning.
- Servers: Ubuntu with systemd, curl and python3. CI tests the scripts on GitHub's Ubuntu runner
  with apt, systemd and the network mocked. Other distributions are untested.
- PC: Windows 10 or 11 with Node 22+.

## Coming from discord-cve-monitor

The hub is discord-cve-monitor with more added. Your data folder loads as it is and keeps its
channels and role, and the commands move from `/cve` to `/nethersec`. See
[Migrating from discord-cve-monitor 1.x](docs/hub/README.md#migrating-from-discord-cve-monitor-1x).

## Contributing and security

[AGENTS.md](AGENTS.md) covers the layout, the tests and the rules a change has to keep. Report a
vulnerability privately as [SECURITY.md](SECURITY.md) describes, not in a public issue.

## License

[MIT](LICENSE)
