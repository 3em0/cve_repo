#!/bin/sh
# Container-side probe: measure how far each state-slot copy writes past the end of
# the host-side state vector (see gdb_overrun.gdb).  Command line identical to
# run_inside.sh.
set +e
mkdir -p /pocketrce/logs
setarch -R gdb -q -batch -x /pocketrce-poc/gdb_overrun.gdb --args \
  /src/llamacpp/build/bin/llama-tts \
  -m /pockettts/pocket-tts.gguf \
  --mmproj /pocketrce/artifact/mmproj_evil_pockettts_worldg31.gguf \
  -p "Hello, this is a test of the pocket text to speech model." \
  -n 64 -t 4 --seed 42 --no-mmproj-offload \
  -o /pocketrce/logs/probe_overrun.wav
echo "GDB_EXIT=$?"
