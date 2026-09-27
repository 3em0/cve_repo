#!/usr/bin/env bash
# Copy the reproduction kit next to the environment it reproduces in, so the
# commands a human types stay short.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${REPRO_ROOT:-$HOME/cve_repro_modelspec}/poc"
mkdir -p "$DEST"
cp -f "$HERE"/*.py "$HERE"/*.sh "$HERE"/*.json "$DEST"/
echo "kit deployed to $DEST"
ls -1 "$DEST"
