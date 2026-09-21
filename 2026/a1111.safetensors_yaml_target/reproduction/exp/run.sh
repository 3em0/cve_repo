#!/usr/bin/env bash
# build -> run twice -> byte-compare result.json -> remove the per-root image.
# Exit code is the verdict.  Must be executed on the host that owns the docker
# daemon (.37 for wave B).
set -uo pipefail

ROOT_KEY=a1111.safetensors_yaml_target
RUNID=${RUNID:-r1}
IMG="mbe2e/v/${ROOT_KEY}:${RUNID}"
PROD_IMG=mbe2e/prod:a1111-82a973c0

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE=$(dirname "$HERE")
CTX="$BASE/.buildctx"
LOGS="$HERE/logs"
mkdir -p "$LOGS"

echo "== [1/5] build artifact (deterministic, official writer API) =="
if [ -n "$(ls -A "$BASE/example/artifact" 2>/dev/null)" ]; then
  echo "using the committed artifact in example/artifact (safetensors serialises __metadata__ from a HashMap, so re-running the writer can reorder keys and change the file hash without changing behaviour)"
else
  docker run --rm --label mbe2e=1 -v "$BASE/example":/ex -w /ex "$PROD_IMG" \
      python /ex/build_artifact.py > "$LOGS/build_artifact.log" 2>&1 || { echo "artifact build failed"; tail -20 "$LOGS/build_artifact.log"; exit 2; }
  tail -3 "$LOGS/build_artifact.log"
fi

echo "== [2/5] build per-root image =="
rm -rf "$CTX"; mkdir -p "$CTX"
cp "$BASE/Dockerfile" "$BASE/entrypoint.sh" "$HERE/drive.py" "$CTX/"
cp "$BASE/config.json" "$CTX/" 2>/dev/null || true
cp /home/xtian/mbe2e/treehash.py "$CTX/treehash.py" 2>/dev/null || cp "$BASE/../scripts/treehash.py" "$CTX/treehash.py"
cp -a "$BASE/example/artifact" "$CTX/artifact"
docker build --label mbe2e=1 -t "$IMG" "$CTX" > "$LOGS/build.log" 2>&1 || { echo "image build failed"; tail -30 "$LOGS/build.log"; exit 2; }

echo "== [3/5] lint drive.py =="
LINT=$(ls "$BASE/../scripts/lint_drive.py" /home/xtian/mbe2e/lint_drive.py 2>/dev/null | head -1)
python3 "$LINT" "$HERE/drive.py" || exit 3

RC=0
for n in 1 2; do
  echo "== [4/5] run $n (--network none) =="
  OUTDIR="$LOGS/run$n"
  rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
  CN="mbe2e_${ROOT_KEY//./_}_${RUNID}_$n"
  docker rm -f "$CN" >/dev/null 2>&1
  docker run --name "$CN" --network none --label mbe2e=1 \
      --memory 24g --cpus 8 --pids-limit 4096 \
      "$IMG" > "$OUTDIR/container_stdout.log" 2>&1
  echo "run$n exit=$?"
  docker cp "$CN":/evidence/. "$OUTDIR/" >/dev/null 2>&1
  docker rm -f "$CN" >/dev/null 2>&1
done

echo "== [5/5] determinism =="
if cmp -s "$LOGS/run1/result.json" "$LOGS/run2/result.json"; then
  echo "rerun_identical=1"
else
  echo "rerun_identical=0"; diff "$LOGS/run1/result.json" "$LOGS/run2/result.json" | head -40; RC=4
fi

cp "$LOGS/run1/result.json" "$HERE/result.json" 2>/dev/null
( cd "$LOGS/run1" && sha256sum result.json browser_trace.zip logs/* 2>/dev/null ) > "$HERE/SHA256SUMS"
grep -q '"verdict": "E2_product_e2e"' "$HERE/result.json" 2>/dev/null || { [ "$RC" = 0 ] && RC=5; }

echo "== cleanup per-root image =="
docker rmi -f "$IMG" >/dev/null 2>&1 && echo "rmi $IMG"
rm -rf "$CTX"
exit "$RC"
