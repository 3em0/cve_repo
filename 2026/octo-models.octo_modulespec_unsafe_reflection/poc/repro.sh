#!/usr/bin/env bash
# One-shot reproduction: build the packages, load the positive one, delete the
# marker, load the negative one, show /out after each step.
set -uo pipefail
cd "$(dirname "$0")"

SINK=/out/octo_modulespec_sink_marker
rm -f "$SINK"

python make_poc.py

echo
echo "=== positive package ==="
python run_load.py checkpoints/octo-checkpoint-positive
echo
ls -la /out

rm -f "$SINK"
echo
echo "=== negative package (delay=true) ==="
python run_load.py checkpoints/octo-checkpoint-negative
echo
ls -la /out
