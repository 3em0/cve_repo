#!/usr/bin/env bash
# Source this once per shell; every step below then works with short commands.
#   source env.sh
export REPRO_ROOT="${REPRO_ROOT:-$HOME/cve_repro_modelspec}"
export COMFY_ROOT="$REPRO_ROOT/src/ComfyUI"
export RUN_DIR="$REPRO_ROOT/run"
export ART_DIR="$REPRO_ROOT/artifacts"
export MARKER_PATH="$RUN_DIR/staged_marker.json"
export PYTHON="$REPRO_ROOT/venv/bin/python"
export COMFY_SHA=387f98aa2822f684b8597959a52a467d88cc4806
export NODE_SHA=609f3afaa74b2f88ef9ce8d939626065e3247469
export VICTIM_INIT="$COMFY_ROOT/custom_nodes/Victim-Demo-Pack/__init__.py"
export VI="$VICTIM_INIT"
export ESCALATED="$COMFY_ROOT/temp"
export STAGED_SHA="$(sha256sum "$ART_DIR/staged_init.py" 2>/dev/null | cut -d' ' -f1)"
export PATH="$REPRO_ROOT/venv/bin:$PATH"
