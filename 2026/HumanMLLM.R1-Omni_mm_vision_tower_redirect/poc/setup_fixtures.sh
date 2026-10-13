#!/bin/bash
# One-time fixture setup for the R1-Omni directed-model-load PoC.
#
# Creates the directories the artifact and the victim's loader need, and hands
# them to the unprivileged user that runs the PoC:
#
#   /model                                  artifact root a victim downloads and loads
#   /model-negative                         byte-identical control artifact root
#   /external                               outside any artifact
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

mkdir -p /model /model-negative /external
mkdir -p /mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V
chown -R "$VICTIM" /model /model-negative /external /mnt/data

echo "fixtures ready, owner=$VICTIM"
ls -ld /model /model-negative /external /mnt/data /mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V
