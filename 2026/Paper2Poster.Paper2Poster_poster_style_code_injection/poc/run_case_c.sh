#!/usr/bin/env bash
# Case C - negative control: identical carrier, only section_title_vertical_align differs
# ("bottom", the value the repository itself ships). Nothing may be executed.
set -x
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python kit/make_poc.py --case benign --out work-benign --marker "$PWD/markers/control.txt"
python kit/run_repro.py --workspace work-benign/paper-workspace \
    --marker markers/control.txt \
    --launch-from run-dir --run-dir run-cwd-C
