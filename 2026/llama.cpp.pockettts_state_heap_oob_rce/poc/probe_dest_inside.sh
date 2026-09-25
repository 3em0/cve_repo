#!/bin/sh
# Container-side probe: run the victim under gdb and print the heap addresses the
# state buffer is copied into (see gdb_dest.gdb).  The command line is identical to
# run_inside.sh - the prompt, -n/-t/--seed and the artifact name all affect the
# deterministic heap layout, so they must not be edited.
set +e
mkdir -p /pocketrce/logs
setarch -R gdb -q -batch -x /pocketrce-poc/gdb_dest.gdb --args \
  /src/llamacpp/build/bin/llama-tts \
  -m /pockettts/pocket-tts.gguf \
  --mmproj /pocketrce/artifact/mmproj_evil_pockettts_worldg31.gguf \
  -p "Hello, this is a test of the pocket text to speech model." \
  -n 64 -t 4 --seed 42 --no-mmproj-offload \
  -o /pocketrce/logs/probe_dest.wav
echo "GDB_EXIT=$?"
