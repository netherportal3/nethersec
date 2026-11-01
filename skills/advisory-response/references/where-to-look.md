# Where to look

Read-only commands for each surface. Replace `CVE-2026-12345`, `somepkg` and the paths with
yours. On a server, use one pinned SSH key and one box at a time.

## The hub

MCP: `nethersec_alerts` (all kinds), then read titles and details for the id or package.

State API (token from a mode-600 file, see the `setup-hub` skill):

```sh
{ printf 'header = "Authorization: Bearer '; tr -d '\n' < ~/.config/nethersec/api-token; printf '"\n'; } \
  | curl -sS -K - http://127.0.0.1:8787/v1/state > /tmp/nethersec-state.json
jq -r '.cards[] | select(((.title // "") + " " + (.detail // "")) | test("CVE-2026-12345|somepkg"; "i"))
       | "\(.kind) \(.severity) \(.source // "-") \(.title)"' /tmp/nethersec-state.json
jq -r '.containers[] | "\(.box) \(.container) \(.image) \(.os) \(.osVersion)"' /tmp/nethersec-state.json
jq -r '.rebootPending[] | "\(.source) since=\(.since) livepatch=\(.livepatch) uncovered=\(.uncovered)"' /tmp/nethersec-state.json
```

A repo card's title names the advisory by its GHSA or OSV id, not the CVE, so keep the package
name in the pattern. The state file names every box and container: delete it when done.

Discord: `/nethersec findings`, `/nethersec alerts`, `/nethersec reboots`, `/nethersec hosts`.

## Repos

The hub's repo cards cover npm, pnpm, Yarn, Bun (`bun.lock`), exact pip pins, uv and Poetry,
on each repo's default branch. For anything else, search the repos the person names (shallow
clones are enough):

```sh
git clone --depth 1 --filter=blob:none https://github.com/example/app.git /tmp/check/app
grep -rn --include='*.lock' --include='*lock*.json' --include='*.toml' --include='go.sum' \
  --include='Cargo.lock' --include='requirements*.txt' --include='Dockerfile*' -i 'somepkg' /tmp/check/app
```

A `requirements.txt` line that is not an exact `==` pin cannot be checked by the hub.

## Servers

```sh
dpkg-query -W -f='${Package} ${Version}\n' 'somepkg*' 2>/dev/null
apt-cache policy somepkg                 # installed, candidate, and which pocket has it
apt-get -s dist-upgrade | grep '^Inst' | grep -i somepkg
uname -r; ls /boot/vmlinuz-*
/snap/bin/canonical-livepatch status --verbose 2>/dev/null | grep -i -A2 'CVE-2026-12345'
sudo needrestart -b                      # services still on old library code
sudo ss -Htulnp                          # what listens, and which process
ps -eo pid,user,args | grep -i '[s]omepkg'
lsmod | grep -i somemodule               # a kernel bug in a module: is it loaded?
```

For Ubuntu, the CVE's status per release is on `https://ubuntu.com/security/CVE-2026-12345`.
"Needed", "deferred" or "pending" there is not a released fix.

A binary that is not a package (a vendor tarball, a Go binary): run its `--version`, or for Go
`go version -m <binary>` shows the Go version and module versions it was built with.

## Containers

```sh
docker ps --format '{{.Names}} {{.Image}}'
docker image inspect --format '{{.Id}} {{.Created}}' <image>
docker exec <container> sh -c 'cat /etc/os-release; somepkg --version' 2>/dev/null
```

`docker exec` runs a command inside the container: keep it to reads like these. The hub's
container check covers Debian, Ubuntu and Alpine OS packages only.

## PCs

```powershell
winget list --id Vendor.App
node $env:USERPROFILE\.nethersec-pc\pc-security-report.mjs --dry-run
```

## Is the fix live?

| Thing | Live when |
|---|---|
| Kernel | `uname -r` is the fixed version, or Livepatch lists the CVE as applied |
| A library on the host | the package is upgraded and `needrestart -b` names no service for it |
| A service binary | the running process was started after the upgrade (`ps -o lstart= -p <pid>`) |
| A container | the container was recreated from the new image (`docker inspect --format '{{.Image}}' <container>` matches the new image id) |
| A language runtime | the running process reports the fixed version, not only the lockfile or Dockerfile |
| A repo dependency | the fix is merged to the default branch and the app was deployed from that commit |
