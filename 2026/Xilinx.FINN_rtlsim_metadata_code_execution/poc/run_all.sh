#!/bin/bash
# One-shot reproduction of the FINN model-package eval() issue.
#
#   source <finn-env>            # venv with finn + qonnx + onnx installed
#   export FINN_ROOT=~/work/finn-src
#   export FINN_BUILD_DIR=~/work/finn_build_dir
#   bash run_all.sh
#
# It builds both packages from the carrier, runs the malicious one, shows the
# canary, then runs the negative control and shows that no canary appears.
set -u
cd "$(dirname "$0")"
PY=${PY:-python}
CANARY=/tmp/finn_eval_canary.txt

echo "=== [1/5] rebuild the two model packages from the carrier ==="
"$PY" make_poc.py

echo
echo "=== [2/5] run the malicious package: python -m finn.builder.build_dataflow artifacts/evil ==="
rm -f "$CANARY"
rm -rf artifacts/evil/output
"$PY" -m finn.builder.build_dataflow artifacts/evil 2>&1 | tail -12

echo
echo "=== [3/5] payload side effect ==="
if [ -f "$CANARY" ]; then
    cat "$CANARY"
else
    echo "no canary - exploit did not fire"
fi

echo
echo "=== [4/5] negative control: python -m finn.builder.build_dataflow artifacts/benign ==="
rm -f "$CANARY"
rm -rf artifacts/benign/output
"$PY" -m finn.builder.build_dataflow artifacts/benign 2>&1 | tail -12

echo
echo "=== [5/5] control side effect ==="
if [ -f "$CANARY" ]; then
    echo "UNEXPECTED: canary present after control run"
    cat "$CANARY"
else
    echo "no canary - control produced no side effect"
fi
