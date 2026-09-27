#!/usr/bin/env bash
# build -> run x2 -> cmp -> clean.  Exit code is the verdict.
set -uo pipefail
ROOT_KEY=kitops.kitfile_model_path_shell_injection
RUNID=${RUNID:-r1}
IMG=mbe2e/v/${ROOT_KEY}:${RUNID}
HERE=$(cd "$(dirname "$0")/.." && pwd)
LOGS="$HERE/exp/logs"
mkdir -p "$LOGS"

echo "== build =="
docker build --network host --label mbe2e=1 -t "$IMG" "$HERE" > "$LOGS/build.log" 2>&1 || { tail -30 "$LOGS/build.log"; exit 20; }; tail -5 "$LOGS/build.log"
docker image inspect "$IMG" --format '{{.Id}}' > "$LOGS/image.txt"
sha256sum "$HERE/Dockerfile" | awk '{print $1}' > "$LOGS/dockerfile.sha256"

CID=$(docker create --label mbe2e=1 "$IMG")
rm -rf "$HERE/example/artifact"; mkdir -p "$HERE/example/artifact"
docker cp "$CID:/artifact/." "$HERE/example/artifact/" >/dev/null
docker rm -f "$CID" >/dev/null

run_once () {
  local n=$1
  rm -rf "$HERE/exp/out$n"; mkdir -p "$HERE/exp/out$n"
  docker run --rm --label mbe2e=1 --network none \
    --memory 6g --cpus 2 --pids-limit 512 \
    -v "$HERE/exp/out$n:/out" \
    "$IMG" python /work/exp/drive.py
}

echo "== run 1 =="; run_once 1; rc1=$?
echo "== run 2 =="; run_once 2; rc2=$?

echo "== determinism =="
cmp "$HERE/exp/out1/result.json" "$HERE/exp/out2/result.json" || exit 21
cp "$HERE/exp/out1/result.json" "$HERE/exp/result.json"

# third, log-harvesting run (same image, same inputs)
docker run --rm --label mbe2e=1 --network none \
  -v "$HERE/exp/out1:/out" -v "$LOGS:/work/exp/logs" "$IMG" \
  python /work/exp/drive.py >/dev/null

( cd "$HERE" && find example exp -type f ! -name SHA256SUMS -print0 \
  | sort -z | xargs -0 sha256sum > exp/SHA256SUMS )

echo "== cleanup =="
docker rmi "$IMG" >/dev/null 2>&1 || true
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ]
