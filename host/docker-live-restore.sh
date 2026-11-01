#!/usr/bin/env bash
# docker-live-restore.sh: turn on Docker's live-restore on this box. Idempotent.
#
# live-restore keeps containers running while dockerd or containerd restarts, so a
# Docker package upgrade (the release-age applier's, or a manual one) no longer stops
# every container on the box. Turning it on restarts no container.
#
# What it does: merges "live-restore": true into /etc/docker/daemon.json (other keys
# kept, the old file backed up beside it), validates the new file with
# `dockerd --validate` before it replaces the old one, then reloads dockerd (SIGHUP,
# which restarts no container) and checks that the daemon reports it on. It refuses on
# a swarm node, where live-restore does not apply.
#
#   sudo bash /opt/nethersec/docker-live-restore.sh            # turn it on
#   bash /opt/nethersec/docker-live-restore.sh --check         # report only
#
# --check exits 0 when it is on, 1 when it is off or Docker does not answer, and 2 when
# Docker is not installed. install.sh --with-applier runs this script, and check 8 of
# security-report.sh cards a box where it is off.
#
# Limits, so nobody over-trusts it:
#   - Docker documents live-restore for patch upgrades. It often holds across minor
#     versions too, but compare `docker ps` uptimes after a big jump.
#   - While dockerd is down, the containers keep running, but Docker's embedded DNS is
#     served by dockerd, so a container opening a new connection by service name can
#     fail for those seconds. On a box where that could lose a write (a database that
#     clients reach by service name), upgrade Docker in a maintenance window and hold
#     its packages the rest of the time.
#
# Env seams (the offline harness test/docker-live-restore.test.sh sets them):
#   HOSTSEC_DOCKER_CMD          docker client (default: docker)
#   HOSTSEC_DOCKERD_CMD         daemon binary used for --validate (default: dockerd)
#   HOSTSEC_SYSTEMCTL_CMD       (default: systemctl)
#   HOSTSEC_DOCKER_DAEMON_JSON  (default: /etc/docker/daemon.json)
#   HOSTSEC_LR_WAIT_SECS        how long to wait for the reload to show (default: 15)
set -euo pipefail

DOCKER="${HOSTSEC_DOCKER_CMD:-docker}"
DOCKERD="${HOSTSEC_DOCKERD_CMD:-dockerd}"
SYSTEMCTL="${HOSTSEC_SYSTEMCTL_CMD:-systemctl}"
CONF="${HOSTSEC_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"
WAIT="${HOSTSEC_LR_WAIT_SECS:-15}"
case "$WAIT" in ''|*[!0-9]*) WAIT=15 ;; esac

CHECK=0
case "${1:-}" in
  --check) CHECK=1 ;;
  '') ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "docker-live-restore: unknown arg '$1'" >&2; exit 2 ;;
esac

if ! command -v "$DOCKER" >/dev/null 2>&1; then
  echo "docker-live-restore: Docker is not installed here, nothing to do."
  [ "$CHECK" -eq 1 ] && exit 2
  exit 0
fi

lr_state() { "$DOCKER" info -f '{{.LiveRestoreEnabled}}' 2>/dev/null; }

if ! state=$(lr_state); then
  echo "docker-live-restore: cannot read 'docker info'. Is dockerd running?" >&2
  exit 1
fi
if [ "$state" = true ]; then
  echo "docker-live-restore: live-restore is on."
  exit 0
fi
if [ "$state" != false ]; then
  echo "docker-live-restore: unexpected answer from docker info: '$state'" >&2
  exit 1
fi
if [ "$CHECK" -eq 1 ]; then
  echo "docker-live-restore: live-restore is OFF. Turn it on: sudo bash $0"
  exit 1
fi

swarm=$("$DOCKER" info -f '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo unknown)
if [ "$swarm" != inactive ]; then
  echo "docker-live-restore: refusing, swarm state is '$swarm'. live-restore does not apply to a swarm node." >&2
  exit 1
fi

conf_dir=$(dirname -- "$CONF")
[ -d "$conf_dir" ] || install -d -m 0755 "$conf_dir"
[ -w "$conf_dir" ] || { echo "docker-live-restore: cannot write $conf_dir (run as root)" >&2; exit 1; }

tmp="$CONF.tmp.$$"
trap 'rm -f "$tmp"' EXIT
# Merge, keeping every other key. A file that is not a JSON object is left alone.
python3 - "$CONF" "$tmp" <<'PY'
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(src):
    with open(src) as f:
        text = f.read().strip()
    if text:
        try:
            cfg = json.loads(text)
        except ValueError as e:
            sys.exit("docker-live-restore: %s is not valid JSON (%s); left unchanged" % (src, e))
if not isinstance(cfg, dict):
    sys.exit("docker-live-restore: %s is not a JSON object; left unchanged" % src)
cfg["live-restore"] = True
with open(dst, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
chmod 0644 "$tmp"
if ! "$DOCKERD" --validate --config-file "$tmp" >/dev/null 2>&1; then
  echo "docker-live-restore: dockerd rejected the merged config; $CONF left unchanged:" >&2
  "$DOCKERD" --validate --config-file "$tmp" >&2 || true
  exit 1
fi

if [ -f "$CONF" ]; then
  bak="$CONF.bak.$(date -u +%Y%m%d-%H%M%S)-liverestore"
  cp -p "$CONF" "$bak"
  echo "docker-live-restore: backed up the old file to $bak"
fi
mv -f "$tmp" "$CONF"
trap - EXIT
echo "docker-live-restore: wrote $CONF"

# SIGHUP: dockerd re-reads its config. No container restarts.
"$SYSTEMCTL" reload docker
i=0
while :; do
  state=$(lr_state || echo unreadable)
  [ "$state" = true ] && break
  [ "$i" -ge "$WAIT" ] && break
  sleep 1; i=$((i + 1))
done
if [ "$state" = true ]; then
  echo "docker-live-restore: live-restore is on. Running containers were not restarted."
  exit 0
fi
echo "docker-live-restore: wrote $CONF but the daemon still reports '$state'. Check 'journalctl -u docker'." >&2
exit 1
