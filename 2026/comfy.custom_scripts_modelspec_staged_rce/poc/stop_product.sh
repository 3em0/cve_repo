#!/usr/bin/env bash
# Stop the real product process started by start_product.sh and wait for it to
# actually exit, so the next start is a real restart and not a no-op.
set -uo pipefail
ROOT="${REPRO_ROOT:-$HOME/cve_repro_modelspec}"
RUN="${RUN_DIR:-$ROOT/run}"
PIDFILE="$RUN/product.pid"

if [ ! -f "$PIDFILE" ]; then
  echo "no pidfile at $PIDFILE -- nothing to stop"
  exit 0
fi
PID="$(cat "$PIDFILE")"
if ! kill -0 "$PID" 2>/dev/null; then
  echo "pid $PID is not running (already stopped)"
  rm -f "$PIDFILE"
  exit 0
fi
kill "$PID"
for _ in $(seq 1 60); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "stopped pid $PID"
    rm -f "$PIDFILE"
    exit 0
  fi
  sleep 1
done
echo "pid $PID did not exit in 60s; sending SIGKILL"
kill -9 "$PID" 2>/dev/null
rm -f "$PIDFILE"
exit 0
