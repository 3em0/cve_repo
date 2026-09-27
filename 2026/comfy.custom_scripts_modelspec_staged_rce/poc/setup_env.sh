#!/usr/bin/env bash
# Real-stack bootstrap for the ComfyUI-Custom-Scripts "modelspec.description" chain.
# Runs inside WSL/Linux (this host: kali-linux). Idempotent -- re-running resumes.
#
#   wsl -d kali-linux -e bash -lc 'bash /mnt/e/.../poc/setup_env.sh'
#
# Everything lands under $HOME/cve_repro_modelspec (NOT in the report directory):
#   src/ComfyUI                     host application, pinned
#   src/ComfyUI-Custom-Scripts      vulnerable node pack, pinned
#   venv/                           python env with the real dependency set
#   logs/                           install transcripts
set -uo pipefail

COMFY_REPO=https://github.com/comfyanonymous/ComfyUI
COMFY_SHA=387f98aa2822f684b8597959a52a467d88cc4806
NODE_REPO=https://github.com/pythongosssss/ComfyUI-Custom-Scripts
NODE_SHA=609f3afaa74b2f88ef9ce8d939626065e3247469

ROOT="$HOME/cve_repro_modelspec"
SRC="$ROOT/src"
VENV="$ROOT/venv"
LOGS="$ROOT/logs"
mkdir -p "$SRC" "$LOGS"

step() { echo; echo "=== [$(date -u +%H:%M:%S)] $* ==="; }

step "system"
python3 -V
git --version

step "clone $NODE_REPO @ $NODE_SHA"
if [ ! -d "$SRC/ComfyUI-Custom-Scripts/.git" ]; then
  git clone --quiet "$NODE_REPO" "$SRC/ComfyUI-Custom-Scripts" || { echo "NODE CLONE FAILED"; exit 9; }
fi
git -C "$SRC/ComfyUI-Custom-Scripts" fetch --quiet origin "$NODE_SHA" 2>/dev/null
git -C "$SRC/ComfyUI-Custom-Scripts" checkout --quiet "$NODE_SHA" || { echo "NODE CHECKOUT FAILED"; exit 9; }
echo "node pack HEAD = $(git -C "$SRC/ComfyUI-Custom-Scripts" rev-parse HEAD)"

step "clone $COMFY_REPO @ $COMFY_SHA"
if [ ! -d "$SRC/ComfyUI/.git" ]; then
  git clone --quiet "$COMFY_REPO" "$SRC/ComfyUI" || { echo "COMFY CLONE FAILED"; exit 9; }
fi
git -C "$SRC/ComfyUI" fetch --quiet origin "$COMFY_SHA" 2>/dev/null
git -C "$SRC/ComfyUI" checkout --quiet "$COMFY_SHA" || { echo "COMFY CHECKOUT FAILED"; exit 9; }
echo "comfy HEAD = $(git -C "$SRC/ComfyUI" rev-parse HEAD)"

step "install the node pack where ComfyUI actually loads it"
mkdir -p "$SRC/ComfyUI/custom_nodes"
if [ ! -d "$SRC/ComfyUI/custom_nodes/ComfyUI-Custom-Scripts/.git" ]; then
  cp -a "$SRC/ComfyUI-Custom-Scripts" "$SRC/ComfyUI/custom_nodes/ComfyUI-Custom-Scripts"
fi
echo "custom_nodes:"; ls -1 "$SRC/ComfyUI/custom_nodes"
echo "node pack HEAD = $(git -C "$SRC/ComfyUI/custom_nodes/ComfyUI-Custom-Scripts" rev-parse HEAD)"

step "venv"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV" || { echo "VENV FAILED (python3-venv missing?)"; exit 10; }
fi
"$VENV/bin/python" -V
"$VENV/bin/python" -m pip install --quiet --upgrade pip wheel 2>&1 | tail -3

step "install real dependency set (ComfyUI requirements.txt)"
"$VENV/bin/python" -m pip install -r "$SRC/ComfyUI/requirements.txt" 2>&1 | tail -25
echo "requirements exit=$?"

step "install playwright"
"$VENV/bin/python" -m pip install playwright 2>&1 | tail -5
"$VENV/bin/python" -m playwright install chromium 2>&1 | tail -5

step "pin check"
git -C "$SRC/ComfyUI" rev-parse HEAD
git -C "$SRC/ComfyUI-Custom-Scripts" rev-parse HEAD
"$VENV/bin/python" -c "import torch, aiohttp, safetensors; print('torch', torch.__version__); print('aiohttp', aiohttp.__version__); print('safetensors', safetensors.__version__)"

echo
echo "BOOTSTRAP-DONE"
