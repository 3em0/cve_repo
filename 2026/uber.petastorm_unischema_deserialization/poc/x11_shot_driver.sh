#!/bin/bash
# Capture REAL terminal-window screenshots for the petastorm unischema-unpickling PoC.
#
# What this does
# --------------
#   * starts a private X server (Xvfb) reachable only over 127.0.0.1, so the terminal
#     window it hosts never appears on the physical Windows desktop at all;
#   * runs a real xterm on that display, and inside it a real interactive shell in the
#     Docker container that holds the PoC;
#   * types the PoC commands one at a time with xdotool (real X key events into a real
#     terminal emulator), exactly the way a person would work through the case;
#   * captures the terminal window's own pixels with ImageMagick `import`.
#
# Nothing is synthesised or re-drawn: every pixel in the resulting PNG is rendered by a
# real terminal emulator from the real stdout/stderr of the really executed commands.
#
# Why not on the physical desktop: this machine's desktop was occupied by a concurrent
# automation session driving its own always-on-top terminal. Opening and capturing a
# window there would have covered that session's window and swapped keystroke targets.
#
# Usage:  bash x11_shot_driver.sh [output-dir]
set -u

XDISPLAY_NUM=":77"
XDISPLAY="127.0.0.1:77"
SCREEN="1600x900x24"
IMAGE="petastorm-poc:1"
CONTAINER="petastorm-poc-lab"
TITLE="petastorm-poc"
OUT="${1:-/mnt/e/Reproduce/uber-petastorm_rce_2026-10-05/screenshots}"
PIDFILE="/tmp/petastorm-xvfb.pid"

# --- clean slate -------------------------------------------------------------
# pgrep -x matches the process name only, so this cannot match the driver's own command
# line (a `pkill -f 'Xvfb :77'` would match and kill this very shell).
for p in $(pgrep -x Xvfb); do kill "$p" 2>/dev/null; done
for p in $(pgrep -x xterm); do kill "$p" 2>/dev/null; done
sleep 1
rm -f /tmp/.X77-lock
docker rm -f "$CONTAINER" >/dev/null 2>&1

Xvfb "$XDISPLAY_NUM" -screen 0 "$SCREEN" -listen tcp >/tmp/petastorm-xvfb.log 2>&1 &
echo $! >"$PIDFILE"
sleep 3

# --- the container under test ------------------------------------------------
docker run -d --name "$CONTAINER" -w /poc "$IMAGE" sleep infinity >/dev/null

# --- a real terminal emulator on the private display -------------------------
DISPLAY="$XDISPLAY" xterm -T "$TITLE" -geometry 150x38 \
      -fa "DejaVu Sans Mono" -fs 11 -b 6 \
      -bg "#10141a" -fg "#e8e8e8" -xrm 'XTerm*scrollBar:false' \
      -e bash -lc "docker exec -it $CONTAINER bash" >/tmp/petastorm-xterm.log 2>&1 &
sleep 4

# Locate the terminal by X class, not by title: the shell inside the container sets the
# window title to its prompt ("root@<id>: /poc"), overwriting xterm's -T title.
WIN=""
for _ in $(seq 1 20); do
    WIN=$(DISPLAY="$XDISPLAY" xdotool search --class XTerm 2>/dev/null | tail -1)
    [ -n "$WIN" ] && break
    sleep 1
done
if [ -z "$WIN" ]; then echo "ERROR: terminal window not found"; exit 1; fi
echo "terminal window id: $WIN"
echo "window title now: $(DISPLAY="$XDISPLAY" xdotool getwindowname "$WIN")"

mkdir -p "$OUT"

send() {
    DISPLAY="$XDISPLAY" xdotool windowfocus "$WIN"
    sleep 0.5
    DISPLAY="$XDISPLAY" xdotool type --delay 22 -- "$1"
    sleep 0.4
    DISPLAY="$XDISPLAY" xdotool key --clearmodifiers Return
    sleep "${2:-1.5}"
}

shot() {
    sleep 0.4
    DISPLAY="$XDISPLAY" import -window "$WIN" "$OUT/$1"
    echo "  captured $1"
}

echo "typing the PoC session into the terminal ..."

send 'python --version' 1.5
send 'python -c "import pyarrow; print(pyarrow.__version__)"' 1.5
send 'python -c "import petastorm; print(petastorm.__version__, petastorm.__file__)"' 2
shot 01-environment.png

send 'python make_poc.py' 9
shot 02-build-datasets.png

send 'find dataset_evil -type f' 1.5
shot 03-dataset-contents.png

send 'python -c "import petastorm.etl.legacy as m; print(m.__file__)"' 2
send 'sed -n "21,48p" /usr/local/lib/python3.10/dist-packages/petastorm/etl/legacy.py' 1.5
shot 04-vulnerable-code.png

send 'python -m petastorm.etl.metadata_util --dataset-url file://$PWD/dataset_benign --schema' 3
shot 05-benign-schema.png

send 'python read_dataset.py dataset_benign' 5
shot 06-benign-read.png

send 'ls -l /tmp/petastorm-rce-proof.txt' 1.5
shot 07-proof-absent.png

send 'python -m petastorm.etl.metadata_util --dataset-url file://$PWD/dataset_evil --schema' 3
shot 08-evil-trigger.png

send 'cat /tmp/petastorm-rce-proof.txt' 1.5
shot 09-proof-file.png

send 'python read_dataset.py dataset_evil' 5
shot 10-make-reader-trigger.png

send 'python -m petastorm.etl.metadata_util --dataset-url file://$PWD/dataset_blocked --schema' 3
shot 11-blocked-control.png

echo "done: $(ls -1 "$OUT"/*.png 2>/dev/null | wc -l) images in $OUT"
