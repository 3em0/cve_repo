#!/usr/bin/env bash
# Case A - attacker-controlled working directory (no config/poster.yaml in the cwd):
# the per-poster poster.yaml next to paper.pdf is the last writer of the merged config,
# so its section_title_vertical_align value reaches the generated PPTX program.
set -x
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python kit/make_poc.py --case evil --out work-evil --marker "$PWD/markers/rce_cwd.txt"
python kit/run_repro.py --workspace work-evil/paper-workspace \
    --marker markers/rce_cwd.txt \
    --launch-from run-dir --run-dir run-cwd-A \
    --dump-code run-cwd-A/generated_program.py
