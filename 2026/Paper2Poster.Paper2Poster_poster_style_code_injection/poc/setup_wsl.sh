#!/usr/bin/env bash
# Paper2Poster PoC - one-command environment setup (run inside WSL).
#
#   bash /mnt/<drive>/<path>/poc/setup_wsl.sh
#
# Creates, under $P2P_WORK (default: $HOME/p2p-repro):
#   Paper2Poster-623d042/   pinned source subset (commit 623d042)
#   kit/                    make_poc.py + run_repro.py
#   venv/                   python3 venv with the sink-path dependencies
#   markers/                empty dir the injected command writes into
#
# The venv is created on the Linux filesystem on purpose: a venv on /mnt/* (NTFS)
# breaks on symlinks.
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${P2P_WORK:-$HOME/p2p-repro}"
REV="623d042"
NAME="Paper2Poster-$REV"
MIN_DEPS=(pyyaml python-pptx pillow playwright openai mistralai numpy json_repair
          python-Levenshtein lxml pdf2image rich tenacity requests pydantic python-dotenv)

echo "== Paper2Poster PoC setup =="
echo "poc dir : $POC_DIR"
echo "work dir: $WORK"

command -v python3 >/dev/null || { echo "python3 is missing - install python3 and python3-venv first"; exit 1; }

mkdir -p "$WORK" "$WORK/markers"
rm -rf "${WORK:?}/$NAME"
mkdir -p "$WORK/$NAME"
cp -r "$POC_DIR/$NAME/." "$WORK/$NAME/"
cp "$POC_DIR/REVISION" "$WORK/$NAME/REVISION"
mkdir -p "$WORK/kit"
cp "$POC_DIR/make_poc.py" "$POC_DIR/run_repro.py" "$WORK/kit/"
cp "$POC_DIR"/run_case_*.sh "$WORK/kit/"

if [ ! -x "$WORK/venv/bin/python" ]; then
    python3 -m venv "$WORK/venv"
fi
"$WORK/venv/bin/pip" install -q --upgrade pip
"$WORK/venv/bin/pip" install -q "${MIN_DEPS[@]}"

echo
echo "== environment =="
"$WORK/venv/bin/python" -c "import sys, yaml, pptx; print('python     ', sys.version.split()[0]); print('PyYAML     ', yaml.__version__); print('python-pptx', pptx.__version__)"
echo "revision   : $(head -1 "$WORK/$NAME/REVISION")"
echo
echo "next:"
echo "  cd $WORK"
echo "  source venv/bin/activate"
echo "  python kit/make_poc.py --case evil --out work-evil --marker $WORK/markers/rce.txt"
echo "  python kit/run_repro.py --workspace work-evil/paper-workspace --marker markers/rce.txt --launch-from run-dir --run-dir run-cwd"
