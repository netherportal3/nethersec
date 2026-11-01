# Security

## Reporting a vulnerability

Please report security problems privately, not in a public issue: use **Report a vulnerability** on
this repository's **Security** tab. nethersec is maintained in spare time, so there is no guaranteed
response time, but private reports are read and answered.

Useful to include: the part (hub, host, pc, skills), the version or commit, what an attacker needs
(a box key, network access to the hub, a Discord account in the server, a malicious feed or
lockfile), and what they get.

## What each part sends, stores and changes

### Hub

- Listens on `127.0.0.1:8787` by default (with Docker Compose, on the host's loopback). Reports need
  a key; the state API needs its own token and is off until you set one. Put it behind HTTPS or a
  private network before boxes reach it.
- Stores `state.json` and `keys.txt` in its data folder and writes them readable by their owner
  only. Keys are kept as SHA-256 hashes. A key can send reports only for its own box, and a box
  cannot close its own security alert: when boxes report a host card or a container image card
  fixed, the card says so and waits for a person to press Resolve.
- Contacts Discord; `api.github.com` with your token, read requests only, to list repos, download
  lockfiles (never your source code) and read advisories; `registry.npmjs.org` and `api.osv.dev`
  with dependency names and versions (not repo names); and the feeds you list in `watch.json`
  (GitHub advisories, RSS, CISA KEV, NVD and Ubuntu for the kernel feed). OSV also gets the OS
  package names and versions that your servers report for their containers.
- Treats everything it receives as untrusted: lockfiles, feeds and box reports are size-capped and
  parsed defensively, and text from them is escaped so it cannot ping anyone or hide a link.
- Runs in one Discord server and leaves any other server it is added to.

### Host scripts

- Run as root from `/opt/nethersec`, owned by root. The installer refuses, and the detector later
  raises an alert, if a script or a directory on that path (one without the sticky bit) is
  world-writable.
- The detector and the status script only read: simulated apt, journald, `ss`, `sshd -T`,
  `docker cp` of container package databases (nothing runs inside a container). The detector
  contacts your report URL and, only while an update or reboot is pending, Ubuntu's CVE data to grade
  it.
- The key lives in `/etc/nethersec/report.env` (mode 600) and reaches `curl` on stdin, never on a
  command line. The state in `/var/lib/nethersec`, which says what is not patched yet, is
  readable by root only.
- What changes the system, and only when you install or arm it: the applier (from its first run
  it holds updates back while they age; it installs nothing until you set
  `HOSTSEC_APPLY_DRYRUN=0`), `install.sh --with-applier` (it also installs `python3-apt` if
  missing and turns on Docker live-restore), the flood blocker (off until
  `HOSTSEC_FLOOD_MITIGATE=1`), and the mitigation scripts you run by hand. Each has a kill switch
  or a way to undo it in its doc.

### PC scanner

- Runs as your user, never elevated, and only reads (Windows Update search, Defender and firewall
  status, winget, runtime versions, WSL package simulations). Outside its own folder it changes two
  things: `apt-get update` refreshes a running WSL distro's package lists, and winget refreshes its
  own source lists.
- Contacts your hub or webhook, and public release feeds (nodejs.org, endoflife.date, go.dev, Azul,
  CISA KEV). It sends them no version number except the Java major in the Azul query, but it asks
  a runtime's feeds only when that runtime is installed, so they can tell you have it. winget and
  Windows Update contact their own services.
- Keeps its key or webhook URL encrypted for your Windows account (DPAPI) in its own file, never on
  a command line. Anything running as you can still decrypt it; see [docs/pc/README.md](docs/pc/README.md).

### Skills

The skills tell an agent to show you what it will change and ask before anything hard to undo
(reboots, firewall or SSH changes, arming the applier or the flood blocker). An agent can still make
mistakes: read what it proposes before you approve it.
