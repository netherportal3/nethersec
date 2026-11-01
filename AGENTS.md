# Working on nethersec

This file is for anyone (person or coding agent) changing this repo. If you only want to
run nethersec, start at [README.md](README.md) and the skills in [skills/](skills/).

## Layout

| Folder | What it is | Language | Tests |
|---|---|---|---|
| `hub/` | The hub: a Discord bot that scans GitHub lockfiles, receives reports from hosts and the PC scanner, watches advisory feeds, and keeps the alert cards | TypeScript, Node 22.9+ | `cd hub && npm ci && npm run typecheck && npm test` |
| `host/` | Scripts for Linux servers: the security detector, the release-age apt applier, the flood detector, and mitigations. The detector, the applier and the flood detector run as systemd timers | POSIX sh, bash, Python 3 (standard library; `apt-introspect.py` also uses `python3-apt`) | `sh host/test/run-all.sh` (needs Linux; see below) |
| `pc/` | The Windows PC scanner, a scheduled task | Node `.mjs`, PowerShell | `node --test "pc/test/*.test.mjs"` |
| `skills/` | Agent skills (SKILL.md), also served as a Claude Code plugin | Markdown | read them |
| `docs/` | How each part works, and the report protocol | Markdown | |

The parts talk only through the report protocol in [docs/report-protocol.md](docs/report-protocol.md).
Change it there first, then in every part that speaks it.

## Rules that keep it safe

These are the design rules. A change that breaks one needs a very good reason in its PR.

1. **Cannot read is never all-clear.** A check that fails to read sends nothing for its own
   signal. It never reports a `0`, never sends `resolved`, and folds into one can't-read alert
   (`monitor-unreadable` on a host) instead.
2. **Transition-only.** Report when something changes (raise once, clear once). A standing
   problem re-surfaces on a slow timer, never on every run.
3. **Page only for what needs a person now.** Routine patching opens no card. A page needs
   patching that stopped (a stuck High or Critical fix, a failing applier), an exploited bug, a
   new critical advisory or malware, a service down, or an active attack. Everything else is a
   quiet card or a note.
4. **A box cannot close its own security alert.** It can say "this looks fixed"; a person resolves.
5. **Anything that acts ships dark.** The applier and the flood blocker start in dry-run (the
   applier still holds updates while they age, but installs nothing) and are armed per box after
   watching them. A mitigation does nothing until it is run.
6. **Fail toward patched.** The applier's kill switch releases its holds.
7. **Act fast on obvious signals, confirm briefly on ambiguous ones.** Never a long fixed timer
   before acting on a security signal.
8. **Scripts never crash a timer.** The host scripts a timer runs always exit 0 and never page on
   their own errors.
9. **No secret on a command line.** Keys go through files with mode 600 or stdin
   (`curl -K -`), never argv, where other users can read them.

## Public repo hygiene

This repo is public. Never commit:

- real hostnames, IP addresses, domains, Discord IDs, tokens, keys or key hashes;
- anything that describes one specific deployment (which boxes exist, what runs where, open
  ports, allowlists, tuned thresholds);
- names of private repos, issue numbers from them, or people;
- test fixtures that look like real secrets (build them from pieces at runtime instead), or
  files named like real manifests or env files outside `test/` folders.

Examples use `example.com`, `203.0.113.0/24` and `198.51.100.0/24` (documentation ranges),
box names like `web1` and `db1`, and Discord IDs like `123456789012345678`.

## Claims

Every sentence in a README or doc that says nethersec does something must be true of the code
in this commit, and every "tested" must point at a test that runs in CI. When unsure, say less.
Known gaps go in the doc next to the feature, not in a separate list nobody reads.

## Style

- Plain, short sentences. US spelling. No em-dashes in docs or user-facing strings.
- Shell: POSIX `sh` unless the file already needs bash. `set -u`. Quote every expansion.
- All text files use LF line endings (`.gitattributes` enforces it; PowerShell files are CRLF).
- Dependencies: the hub has two runtime dependencies and the PC scanner has none. Adding one
  needs a reason. npm installs never run install scripts (`.npmrc`), and new versions wait 7 days
  (`npm install --before=<date 7 days ago>`; Dependabot has the same cooldown).

## Running the host tests on Windows or macOS

The host harnesses mock apt, journald, Docker and the network, but they need a Linux userland:

```sh
docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 \
  sh -c 'apt-get update -qq && apt-get install -y -qq python3 >/dev/null && sh host/test/run-all.sh'
```

From Git Bash on Windows, prefix it with `MSYS_NO_PATHCONV=1`.

## Commits and PRs

Conventional commits (`type(scope): subject`, scopes `hub`, `host`, `pc`, `skills`, `docs`).
CI must be green. A change to what a user sees or sets updates the matching doc in the same PR.
