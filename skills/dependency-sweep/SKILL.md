---
name: dependency-sweep
description: Fix one dependency advisory across many repos safely, from a nethersec repo card or a list of repos. Checks the fixed release before trusting it (age, maintainer, install scripts, tarball diff), makes the smallest lockfile change per repo (update in range, or an override for a transitive dependency), refuses unrelated version changes and downgrades, keeps the release-age cooldown for everything except the fix itself, opens one PR per repo, waits for CI, merges lockfile PRs one at a time, and confirms the hub card closes. Use when someone says "fix this advisory in all repos", "bump <package> everywhere", "sweep the lockfiles", "patch GHSA-... across the org", "clear the nethersec repo cards", or a repo card lists several repos.
---

# Sweep a dependency fix across repos

You end with: one small PR per affected repo, each green in CI, merged (or handed to its owner),
and the hub's repo card closed because the advisory is gone from every repo on it.

Lockfile recipes and the downgrade check are in
[references/lockfile-edits.md](references/lockfile-edits.md).

## Rules

- **Never run install scripts.** `--ignore-scripts` on every npm command; pnpm 10 and later block
  them by default and Bun runs them only for its trusted list, keep it that way. A poisoned
  release usually runs from an install hook.
- **Cooldown for everything but the fix.** New releases wait (7 days is a common floor) because
  hijacked or broken versions are mostly caught within days. Only the fixed version of the
  package in the advisory may be younger, and only after step 2.
- **Smallest diff.** Change only the vulnerable package (and what it newly needs). Any other
  version that moves, and any version that goes down, is a stop: revert and redo it narrower.
- **One PR per repo, one lockfile PR merged at a time per repo.** Two green lockfile PRs can make
  a broken lockfile together; re-check the default branch after each merge.
- **Not reachable is not a reason to skip.** Note reachability in the PR; fix it anyway.
- Do not push to a repo's default branch, change branch protection, or merge in a repo the
  person does not own. Open the PR and say who has to merge it.
- No token on a command line or in chat; use the git and `gh` login the person already has.

## 1. Collect the work

From the card: the advisory id, the package, the ecosystem, and per repo the installed version
and the fixed version. (`/v1/state` and `nethersec_alerts` with `kind: repo` list the advisory,
the package and the repos still open, but no versions.) Read the advisory itself: a same-day
advisory may show no fixed version yet in the databases the hub reads. Note which release line
each repo is on (a fix may exist for 4.x and 5.x separately).

## 2. Check the fixed release before you trust it

Before any install, check for an active supply-chain incident in that ecosystem (a quick search
for compromised packages this week). Then, for npm:

```sh
npm view somepkg time --json | tail -n 8          # publish dates of the latest versions
npm view somepkg@1.2.4 scripts --json             # reject preinstall, install, postinstall
npm view somepkg@1.2.4 dependencies optionalDependencies --json
npm diff --diff=somepkg@1.2.3 --diff=somepkg@1.2.4 | head -n 200
```

Warning signs: a long-quiet package that suddenly publishes, a new major, new install hooks, new
or optional dependencies, a diff that does more than the advisory describes, a new maintainer.
If the fix is younger than the cooldown and the diff is what the advisory says, it is fine to
take that exact version and nothing else young. For PyPI, compare the release's files and dates
on its project page the same way.

## 3. Per repo: the smallest change

1. Fresh branch from the default branch: `fix(deps): bump somepkg to 1.2.4 for GHSA-xxxx-xxxx-xxxx`.
2. Find how it gets in (`npm ls somepkg --all`, `pnpm why somepkg`, `yarn why somepkg`). A
   direct dependency: raise its range. A transitive one: update within the parent's range if it
   allows the fix, else an override pinned to the fixed version (an override can push a parent
   outside its tested range, so say so in the PR).
3. Update the lockfile only, with scripts off (exact commands per tool in the reference).
4. Run the downgrade check from the reference and read the whole lockfile diff. Expect only the
   target package and anything it newly depends on.
5. Run the repo's own tests and build if it has them. Commit the manifest and lockfile only.
6. Open the PR: the advisory link, from and to versions, why this version, reachability in one
   line, and "lockfile diff checked: no other versions changed, none went down".

## 4. CI and merge

- Wait for CI on the PR. Red on a test the default branch also fails on is not yours: say so.
- Merge one lockfile PR at a time per repo, by the repo's normal rules, then check the default
  branch is green before the next merge there.
- A bot PR that was rebased or regenerated can re-resolve the whole lockfile and move unrelated
  pins, sometimes down. Run the downgrade check on it before merging.

## 5. Confirm

- `/nethersec scan` (or wait for the next scan), then the card: its Status line names each repo
  as the fix lands there, and once the advisory is gone from every repo on the card it turns
  into "Fixed: ...". The status channel posts "Fixed since the last scan" (for advisories at or
  above the alert threshold, and malware).
- Repos the hub does not watch, or lockfiles it skips, need a manual check.
- A fix merged is not a fix deployed: a service built from that repo is fixed once it is
  rebuilt and redeployed from the merged commit.

## 6. Report

A table per repo: PR link, from and to, merged or waiting (and on whom), CI result, and anything
skipped with the reason. List any temporary exception you added (an override, a cooldown
exception for the fix) with the date it can be removed.
