# Changelog

## 0.1.0 (unreleased)

The first release of nethersec. It grows the discord-cve-monitor bot (1.0.0) into a hub and adds
the parts around it.

- **Hub.** The bot, renamed: `/cve` commands become `/nethersec`, and a 1.x data folder loads as is.
  New: a report server (`POST /v1/report`) with one key per box, host alert cards with a Resolve
  button, direct-message delivery for personal devices, a weekly pending-reboot summary, a
  read-only state API (`GET /v1/state`), a read-only MCP server, and optional GitHub scanning.
- **Advisory watch and container check** in the hub: GitHub advisories, RSS feeds and CISA KEV for
  the software you list in `watch.json`, critical network-reachable Linux kernel bugs that Ubuntu has
  not fixed yet, and OSV matching of the OS packages inside your running containers.
- **Host scripts** for Ubuntu servers: the security detector, the release-age apt applier (dry-run
  by default), the flood detector (blocking off by default), mitigations (Docker live-restore, an
  IPv4 IP-options drop, a block on unused network kernel modules), a firewall snapshot, a status
  command with JSON output, and an installer.
- **PC scanner** for Windows: Windows Update, Defender, firewall, apps behind or end of life,
  runtimes, WSL updates, and CISA KEV matches, delivered through the hub or a Discord webhook.
- **Agent skills** and a Claude Code plugin.

Fixed since discord-cve-monitor 1.0.0:

- `/nethersec unmute` with a repo that is not `owner/name` is refused. `/cve unmute` read it as
  no repo and lifted the mute that covers every repo.
