# Lockfile edits and the downgrade check

`somepkg`, `1.2.3` (vulnerable) and `1.2.4` (fixed) stand for yours. Each command updates the
lockfile without running dependency install scripts, within the limits the Bun and Python
notes give. Check the result with the downgrade check at the end, whatever tool made it.

## Cooldown

- If the fixed version is older than the cooldown (7 days), let the tool see only releases older
  than the cooldown, so nothing young slips in beside it. npm:
  `--before="$(date -u -d '7 days ago' +%Y-%m-%d)"` (GNU `date`).
- If the fixed version is younger, you cannot use `--before` (it would hide the fix). Take that
  exact version only, and let the diff check prove nothing else moved.
- pnpm with `minimumReleaseAge` set refuses a young version
  (`ERR_PNPM_NO_MATURE_MATCHING_VERSION`). Exclude that exact version only, in the same PR,
  under `minimumReleaseAgeExclude` in `pnpm-workspace.yaml` (`- somepkg@1.2.4`, if your pnpm
  supports version entries), and note when it can be removed. Never lower the age for
  everything. Two versions of one package go in one entry (`- somepkg@1.2.4 || 2.0.1`); read the
  lockfile afterwards to confirm both applied.

## npm (`package-lock.json`)

Use the npm major the repo already uses: a different one can rewrite the whole file. Check
`lockfileVersion` did not change.

```sh
npm ls somepkg --all                                                    # how it gets in
npm install somepkg@^1.2.4 --package-lock-only --ignore-scripts         # a direct dependency
npm update somepkg --package-lock-only --ignore-scripts                 # transitive, inside its parent's range
```

Transitive and the parent's range does not allow the fix: add an override to `package.json`,
then refresh the lockfile only:

```json
{ "overrides": { "somepkg": "1.2.4" } }
```

```sh
npm install --package-lock-only --ignore-scripts
```

## pnpm (`pnpm-lock.yaml`)

pnpm 10 and later run no dependency build scripts unless they are allowed; do not add `somepkg`
to that list.

```sh
pnpm why somepkg
pnpm update somepkg --lockfile-only
```

An override for a transitive dependency goes under `overrides` (in `pnpm-workspace.yaml` on
pnpm 10, or `pnpm.overrides` in `package.json`), then `pnpm install --lockfile-only`. Prove the
lockfile is consistent with `pnpm install --frozen-lockfile --lockfile-only`.

## Yarn (`yarn.lock`)

- Classic (v1): a `resolutions` entry in `package.json` for a transitive dependency, then
  `yarn install --ignore-scripts`.
- Berry (v2+): `yarn up somepkg@1.2.4` for a direct one, `yarn up -R somepkg` for a transitive
  one, with `--mode=update-lockfile` to skip linking (and with it the build scripts).

## Bun (`bun.lock`)

`bun update somepkg`. Bun runs dependency lifecycle scripts only for trusted packages: those in
`trustedDependencies`, or Bun's built-in list of popular packages. Do not add `somepkg` there.

## Python

- `requirements*.txt`: change the `==` pin. If the fix needs newer dependencies, pin those
  exactly too: the hub checks exact pins only.
- `uv.lock`: `uv lock --upgrade-package somepkg`, then confirm the new version in the lockfile.
- `poetry.lock`: raise the constraint in `pyproject.toml` if needed, then
  `poetry update somepkg --lock` (lockfile only).
- uv and Poetry may build a package that ships only source code, to read its metadata, and that
  runs the package's build code.

## The downgrade check

The rule for every format: list each package's name and version before and after; every change
must be the target package or something it newly needs; no version may go down.

For `package-lock.json` (v2 or v3), on Linux or Git Bash with `jq`:

```sh
lockvers() { jq -r '.packages | to_entries[] | select(.key != "") | "\(.key)\t\(.value.version)"' | tr -d '\r' | LC_ALL=C sort; }
git show HEAD:package-lock.json | lockvers > /tmp/lock-before.tsv
lockvers < package-lock.json > /tmp/lock-after.tsv
diff /tmp/lock-before.tsv /tmp/lock-after.tsv                     # every entry that changed
TAB=$(printf '\t')
LC_ALL=C join -t "$TAB" /tmp/lock-before.tsv /tmp/lock-after.tsv | while IFS="$TAB" read -r p old new; do
  [ "$old" = "$new" ] && continue
  [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n 1)" = "$old" ] && echo "DOWN $p $old -> $new"
done
```

No `DOWN` line, and every line in the `diff` is `somepkg` or a new dependency of it: good.
(The `tr -d '\r'` is for `jq` on Windows, which ends lines with CR LF.)

For other formats, read the changed keys:

```sh
git diff -U0 -- pnpm-lock.yaml | grep -E '^[-+]  [^ ]'      # removed and added name@version keys
git diff -- yarn.lock bun.lock uv.lock poetry.lock requirements*.txt
```

Pair each removed `name@old` with its added `name@new`. A new version lower than the old one, or
a package you did not mean to touch, means: `git checkout -- <manifest> <lockfile>` and redo it
narrower.
