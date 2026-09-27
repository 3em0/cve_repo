#!/usr/bin/env bash
# Local twin of exp/run.sh: builds with Dockerfile.local (this machine's
# equivalent of the original golang:1.25-bookworm build) and otherwise follows
# the same protocol: build -> run x2 -> cmp result.json -> log-harvest run.
# Exit code is the verdict.
set -uo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash for Windows: keep /work/... style args intact
ROOT_KEY=kitops.kitfile_model_path_shell_injection
RUNID=${RUNID:-r1-w11}
IMG=mbe2e/v/${ROOT_KEY}:${RUNID}
HERE=$(cd "$(dirname "$0")" && pwd)
HERE_WIN=$(cygpath -w "$HERE")
LOGS="$HERE/exp/logs"
mkdir -p "$LOGS"

echo "== build (Dockerfile.local) =="
docker build --network host -f "$HERE_WIN\Dockerfile.local" -t "$IMG" "$HERE_WIN" > "$LOGS/build.log" 2>&1 || { tail -30 "$LOGS/build.log"; exit 20; }; tail -5 "$LOGS/build.log"
docker image inspect "$IMG" --format '{{.Id}}' > "$LOGS/image.txt"
sha256sum "$HERE/Dockerfile.local" | awk '{print $1}' > "$LOGS/dockerfile_local.sha256"

CID=$(docker create --label mbe2e=1 "$IMG")
# NOTE: no `docker cp` of /artifact to the Windows host here -- the attack
# payload lives in DIRECTORY NAMES containing `>` (a Win32-reserved character),
# which the Windows-side copy chokes on. The image itself bakes /artifact at
# build time (RUN python /work/example/build_artifact.py /artifact); to obtain
# a host-side copy of the three kits, extract via WSL/POSIX tooling.
docker rm -f "$CID" >/dev/null

run_once () {
  local n=$1
  rm -rf "$HERE/exp/out$n"; mkdir -p "$HERE/exp/out$n"
  docker run --rm --label mbe2e=1 --network none \
    --memory 6g --cpus 2 --pids-limit 512 \
    -v "$HERE_WIN\exp\out$n:/out" \
    "$IMG" python /work/exp/drive.py
}

echo "== run 1 =="; run_once 1; rc1=$?
echo "== run 2 =="; run_once 2; rc2=$?

echo "== determinism =="
cmp "$HERE/exp/out1/result.json" "$HERE/exp/out2/result.json" || exit 21
cp "$HERE/exp/out1/result.json" "$HERE/exp/result.json"

echo "== cleanup =="
# image kept on purpose: the screenshot session (shot_scenario.json) reuses it
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ]
