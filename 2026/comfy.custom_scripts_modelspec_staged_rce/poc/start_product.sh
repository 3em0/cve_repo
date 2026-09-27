#!/usr/bin/env bash
# Start the REAL product the way its own documentation does, detached, and wait
# until it answers on its own /system_stats endpoint (never a fixed sleep).
set -uo pipefail
ROOT="${REPRO_ROOT:-$HOME/cve_repro_modelspec}"
COMFY="${COMFY_ROOT:-$ROOT/src/ComfyUI}"
RUN="${RUN_DIR:-$ROOT/run}"
mkdir -p "$RUN"

PIDFILE="$RUN/product.pid"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "already running: pid $(cat "$PIDFILE")"
  exit 0
fi

LOG="$RUN/product.start$(( $(ls "$RUN"/product.start*.log 2>/dev/null | wc -l) + 1 )).log"
PYTHON="${PYTHON:-python}"
cd "$COMFY" || exit 1
: > "$LOG"
nohup "$PYTHON" main.py --listen 127.0.0.1 --port 8188 --cpu --disable-auto-launch > "$LOG" 2>&1 &
PID=$!
echo "$PID" > "$PIDFILE"
echo "cmd : python main.py --listen 127.0.0.1 --port 8188 --cpu --disable-auto-launch"
echo "cwd : $COMFY"
echo "pid : $PID"
echo "log : $LOG"

for i in $(seq 1 240); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8188/system_stats || true)
  if [ "$CODE" = "200" ]; then
    echo "ready: /system_stats -> 200 after ${i}s"
    exit 0
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "product died during startup:"
    tail -30 "$LOG"
    exit 1
  fi
  sleep 1
done
echo "timeout waiting for /system_stats"
tail -30 "$LOG"
exit 1
