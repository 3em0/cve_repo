#!/usr/bin/env bash
# Case B - the documented launch directory (the repository root, which contains
# config/poster.yaml): the shipped project default is merged AFTER the per-poster file
# and overwrites section_title_vertical_align, so the injected value never reaches the sink.
set -x
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python kit/run_repro.py --workspace work-evil/paper-workspace \
    --marker markers/rce_from_repo_root.txt \
    --launch-from repo-root
