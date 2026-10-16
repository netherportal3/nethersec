# Security

## Reporting a vulnerability

Please report security problems privately, not in a public issue. Use **Report a vulnerability**
on this repository's **Security** tab. You will get a reply within a few days.

## How the bot handles your data

- The GitHub token is sent only to `api.github.com`, only on read (GET) requests. A redirect is
  followed only when it stays on `api.github.com`. The token is never logged, saved or posted.
- The bot never sees your source code. It downloads lockfiles only.
- To look up advisories, it sends the names and versions of your dependencies (no repo names, no
  token) to the public npm advisory endpoint (`registry.npmjs.org`) and to OSV (`api.osv.dev`).
- One install serves one Discord server. It leaves any other server it is added to, so nobody else
  can read your repos' advisories through it.
- Lockfiles are treated as untrusted input: size limits, a cap on files per repo, and parsers that
  stay fast on hostile input.
- Text from advisories and repos is escaped before it is posted, so it cannot format a message,
  hide a link or ping anyone. The only mention the bot ever sends is the CVE Watch role.
