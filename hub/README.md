# nethersec hub

The hub is the Discord bot at the center of nethersec: it takes reports from your servers and PCs,
watches your GitHub repos for vulnerable dependencies, and keeps the alert cards.

- Setup, commands, keys and migrating from discord-cve-monitor 1.x: [docs/hub/README.md](../docs/hub/README.md)
- The HTTP API: [docs/hub/api.md](../docs/hub/api.md)
- The MCP server for agents: [docs/hub/mcp.md](../docs/hub/mcp.md)
- What a report looks like: [docs/report-protocol.md](../docs/report-protocol.md)

```bash
cp .env.example .env    # fill in DISCORD_TOKEN and DISCORD_GUILD_ID
docker compose up -d --build
```
