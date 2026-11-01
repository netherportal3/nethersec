# The hub's MCP server

`hub/mcp/nethersec-mcp.mjs` lets an agent (Claude Code or any MCP client) read the hub's state:
open alerts, hosts, pending reboots and containers. It is read-only: it calls
[`GET /v1/state`](api.md#get-v1state) and nothing else, so an agent can look but not change
anything. People act on alerts in Discord.

It is one file of plain JavaScript that uses only Node's built-ins, so it runs straight from a
clone with Node 22 or newer. There is nothing to install or build.

## Set it up

1. On the hub, turn on the state API: set `NETHERSEC_API_TOKEN` in its `.env` (make one with
   `openssl rand -hex 32`) and restart it.
2. On the machine that runs the agent, put that token in a file only you can read:

   ```sh
   mkdir -p ~/.config/nethersec
   umask 077
   read -rs NS_TOKEN && printf %s "$NS_TOKEN" > ~/.config/nethersec/api-token && unset NS_TOKEN
   ```

   (This needs bash or zsh for `read -s`. `read` and `printf` are shell builtins, so the token is
   never on a command line.)
3. Make sure that machine can reach the hub. If the hub only listens on its own loopback, an SSH
   tunnel works: `ssh -N -L 8787:127.0.0.1:8787 you@your-hub-host`.
4. Add the server to Claude Code:

   ```sh
   claude mcp add \
     --env NETHERSEC_HUB_URL=http://127.0.0.1:8787 \
     --env NETHERSEC_API_TOKEN_FILE="$HOME/.config/nethersec/api-token" \
     --transport stdio nethersec \
     -- node /path/to/nethersec/hub/mcp/nethersec-mcp.mjs
   ```

   Or in a project's `.mcp.json`:

   ```json
   {
     "mcpServers": {
       "nethersec": {
         "command": "node",
         "args": ["/path/to/nethersec/hub/mcp/nethersec-mcp.mjs"],
         "env": {
           "NETHERSEC_HUB_URL": "http://127.0.0.1:8787",
           "NETHERSEC_API_TOKEN_FILE": "/home/you/.config/nethersec/api-token"
         }
       }
     }
   }
   ```

| Variable | What it is |
| --- | --- |
| `NETHERSEC_HUB_URL` | The hub, like `http://127.0.0.1:8787` or `https://hub.example.com`. No path. |
| `NETHERSEC_API_TOKEN_FILE` | A file holding the hub's `NETHERSEC_API_TOKEN`. Read at every call, so a new token needs no restart. |
| `NETHERSEC_API_TOKEN` | The token itself, instead of a file. Prefer the file: an environment value set on a command line can be read by other users of the machine. |

Without the URL and a token, the server still starts. Every tool call then answers with an error
that says which settings to set, and the server writes the same line to stderr once.

## Tools

| Tool | Arguments | What it returns |
| --- | --- | --- |
| `nethersec_overview` | none | Open alerts by kind and severity, each host and how long since it reported, pending reboots, the container count, repo scanning and the open watch cards against their cap (it says so when new watch cards are refused), plus the 10 most severe open alerts. |
| `nethersec_alerts` | `kind` (`repo`, `security`, `uptime`, `watch`), `source`, `severity` (the lowest to include), all optional | The open alerts that match, most severe first. `high` and `warning` rank the same, as do `info` and `low`. |
| `nethersec_host` | `source` (required) | One host: its first and last report, its open alerts, a pending reboot and its containers. |

A successful answer is a short text for the model plus its data as `structuredContent` (the
overview's 10 alerts are in the text only). All three tools are marked read-only. Alert titles and
details are written by the reporting hosts and feeds, so a host that was taken over could write
anything there; the text answers and the server's instructions tell the agent to treat them as
data, never as instructions. If the hub refuses the token, has the state API off, or cannot be
reached, the tool answers with an error that says so; it never shows the token.

## Protocol

JSON-RPC 2.0 over stdio, one message per line. It speaks both eras of MCP:

- **2026-07-28** (the current version): each request carries its protocol version and client
  capabilities in `_meta`; `server/discover` lists the supported versions. A request for a version
  it does not know gets the `-32022` error with the supported list.
- **2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05**: the `initialize` handshake, then
  `notifications/initialized`.

Besides those it answers `ping`, `tools/list` and `tools/call`. Notifications get no answer, and
an unknown method gets `-32601`. It has no resources, prompts or subscriptions.

## What is tested

`hub/test/mcp.test.ts` runs in CI. It checks both eras of the protocol and their errors, every tool
against a real hub HTTP server started in the test (with a fake Discord behind it), the token file,
the wrong-token case, the state-API-off and unreachable cases (with a stubbed fetch), and a spawned
process that starts without any settings and answers over stdio. The `claude mcp add` line follows
Claude Code's documented syntax; the tests do not run Claude Code itself.
