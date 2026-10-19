#!/bin/bash
# One-time fixture setup for the R1-Omni *audio* directed-model-load PoC.
#
# Creates the directories the artifacts and the victim's loader need, and hands
# them to the unprivileged user that runs the PoC:
#
#   /models/humanomni-redirected   main package whose mm_audio_tower points OUTSIDE it
#   /models/humanomni-trusted      byte-identical control package (one field differs)
#   /artifacts/whisper-redirected  the second (audio) model the package redirects to
#   /artifacts/whisper-trusted     the trusted second model used by the control
#   /mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V
#       the path humanomni/model/humanomni_arch.py:83-85 hardcodes for bert-base-uncased
#
# Needs root once. Re-running is harmless.
set -euo pipefail

VICTIM="${1:-${SUDO_USER:-$USER}}"
if [ "$(id -u)" -ne 0 ]; then
  echo "not root -- re-running through sudo for user '$VICTIM'"
  exec sudo -E bash "$0" "$VICTIM"
fi

mkdir -p /models /artifacts
mkdir -p /mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V
chown -R "$VICTIM" /models /artifacts /mnt/data

echo "fixtures ready, owner=$VICTIM"
ls -ld /models /artifacts /mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V
