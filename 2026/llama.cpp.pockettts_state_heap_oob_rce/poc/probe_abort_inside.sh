#!/bin/sh
# Container-side forensics: stop at the allocator abort and dump the planted window.
set +e
mkdir -p /pocketrce/logs
setarch -R gdb -q -batch -x /pocketrce-poc/gdb_abort.gdb --args \
  /src/llamacpp/build/bin/llama-tts \
  -m /pockettts/pocket-tts.gguf \
  --mmproj /pocketrce/artifact/mmproj_evil_pockettts_worldg31.gguf \
  -p "Hello, this is a test of the pocket text to speech model." \
  -n 64 -t 4 --seed 42 --no-mmproj-offload \
  -o /pocketrce/logs/probe_abort.wav
echo "GDB_EXIT=$?"
