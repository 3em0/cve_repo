#!/bin/sh
# Container-side half of the bug-3 reproduction.
#
# This is the command line from the package's own run-exp.sh, unchanged: the
# prompt text, -n/-t/--seed, the output path and the artifact file name all
# affect the deterministic heap layout, so nothing here may be edited.
set +e
/src/llamacpp/build/bin/llama-tts \
  -m /pockettts/pocket-tts.gguf \
  --mmproj /pocketrce/artifact/mmproj_evil_pockettts_worldg31.gguf \
  -p "Hello, this is a test of the pocket text to speech model." \
  -n 64 -t 4 --seed 42 --no-mmproj-offload \
  -o /pocketrce/logs/worldg31_probe70.wav
native_rc=$?
echo "NATIVE_EXIT=$native_rc"
exit 0
