#!/usr/bin/env sh
# run-all.sh: run every host harness (test/*.test.sh with sh, test/*.test.py with
# python3) and fail if none is found or any fails. CI runs this; so can you:
#
#   sh host/test/run-all.sh
#
# The harnesses mock apt, journald, Docker, systemd and the network, so they need no
# root and no network, but they do need a Linux userland with python3 (stdlib only).
set -u

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
n=0; failed=""
for f in "$HERE"/*.test.sh "$HERE"/*.test.py; do
  [ -f "$f" ] || continue
  n=$((n + 1))
  name=$(basename "$f")
  echo "=== $name"
  case "$name" in
    *.py) python3 "$f" ;;
    *) sh "$f" ;;
  esac
  rc=$?
  if [ "$rc" -ne 0 ]; then
    failed="$failed $name"
    echo "=== $name FAILED (exit $rc)"
  fi
done

echo ""
if [ "$n" -eq 0 ]; then
  echo "run-all: no harness found in $HERE"
  exit 1
fi
if [ -n "$failed" ]; then
  echo "run-all: $n harnesses, failed:$failed"
  exit 1
fi
echo "run-all: all $n harnesses passed"
