#!/usr/bin/env bash
# prepare-context.sh — build the docker build context for this case on any machine.
#
# Produces the three context entries the Dockerfiles expect next to this script:
#   dl/go1.25.14.linux-amd64.tar.gz   Go toolchain (same version as the original
#                                     validation's recorded "go1.25.14")
#   src/                              kitops pinned at b6762849b23a599c834e5f14eda5cebcef40b640,
#                                     byte-faithful to the digest in example/expected.json
#   vendor/                           `go mod vendor` output at that pin
#
# After this script, run:  docker build -f Dockerfile.local -t <tag> .
# (or the original `docker build -f Dockerfile ...` if you can pull golang:1.25-bookworm)
#
# Hard-won notes:
#  * The pin's tree contains ONE symlink: CLAUDE.md -> AGENTS.md. On Windows,
#    both git clone and codeload tarballs materialise it as a plain file or a
#    dereferenced copy, which breaks the run-time source-tree digest self-check
#    (exp/treehash.py skips symlinks). We delete the materialised copy so the
#    tree matches the digest exactly; the build does not need the file.
#  * Use the codeload tarball (not git clone) to avoid any git autocrlf /
#    .gitattributes surprises on Windows hosts.
#  * If your containers cannot reach proxy.golang.org (CN networks etc.), we
#    pre-download every module zip via HTTPS from goproxy.cn on the HOST (whose
#    TLS trust store usually differs from the container's) and run
#    `go mod vendor` against a file:// GOPROXY inside a container. go.sum still
#    pins every content hash, so a tampered download fails the vendoring loudly.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash for Windows: keep container-side paths intact
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=b6762849b23a599c834e5f14eda5cebcef40b640
GOVER=1.25.14

mkdir -p "$HERE/dl"
if [ ! -s "$HERE/dl/go$GOVER.linux-amd64.tar.gz" ]; then
  echo "== downloading Go $GOVER toolchain =="
  curl -sL --retry 3 -o "$HERE/dl/go$GOVER.linux-amd64.tar.gz" \
    "https://mirrors.aliyun.com/golang/go$GOVER.linux-amd64.tar.gz"
fi

if [ ! -f "$HERE/src/go.mod" ]; then
  echo "== fetching pinned source (codeload tarball) =="
  curl -sL --retry 3 -o "$HERE/pin.tar.gz" \
    "https://codeload.github.com/kitops-ml/kitops/tar.gz/$PIN"
  mkdir -p "$HERE/src"
  tar -xzf "$HERE/pin.tar.gz" -C "$HERE/src" --strip-components=1
  rm -f "$HERE/pin.tar.gz"
  # CLAUDE.md is a SYMLINK (-> AGENTS.md) at the pin; on Windows extraction
  # dereferences it. Remove the copy so the tree digest matches the one
  # treehash.py computes on a Linux checkout (symlinks are skipped).
  rm -f "$HERE/src/CLAUDE.md"
fi

if [ ! -d "$HERE/vendor/github.com" ]; then
  echo "== vendoring module graph (go mod vendor at the pin) =="
  # Primary: the same image the original Dockerfile builds with.
  if docker run --rm -v "$(cygpath -w "$HERE/src" 2>/dev/null || echo "$HERE/src"):/src" \
       -w /src golang:1.25-bookworm go mod vendor; then
    :
  else
    echo "golang:1.25-bookworm unavailable or module fetch failed; using local toolchain + file proxy"
    mkdir -p "$HERE/goproxy"
    # enumerate the full module closure from go.sum (zip-hash lines)
    grep ' h1:' "$HERE/src/go.sum" | awk '$2 !~ /\/go.mod$/ {print $1" "$2}' | sort -u \
      > "$HERE/modlist.txt"
    while read -r mod ver; do
      esc=$(printf '%s' "$mod" | awk '{s=$0; out=""; for(i=1;i<=length(s);i++){c=substr(s,i,1); if(c ~ /[A-Z]/){out=out "!" tolower(c)} else out=out c}; print out}')
      d="$HERE/goproxy/$esc/@v"; mkdir -p "$d"
      for ext in info mod zip; do
        [ -s "$d/$ver.$ext" ] || curl -sfL --retry 3 \
          -o "$d/$ver.$ext" "https://goproxy.cn/$esc/@v/$ver.$ext"
      done
    done < "$HERE/modlist.txt"
    MSYS_NO_PATHCONV=1 docker run --rm \
      -v "$(cygpath -w "$HERE/dl" 2>/dev/null || echo "$HERE/dl"):/dl:ro" \
      -v "$(cygpath -w "$HERE/goproxy" 2>/dev/null || echo "$HERE/goproxy"):/goproxy:ro" \
      -v "$(cygpath -w "$HERE/src" 2>/dev/null || echo "$HERE/src"):/src" \
      debian:bookworm-slim bash -c \
      "mkdir -p /gotool && tar -C /gotool -xzf /dl/go$GOVER.linux-amd64.tar.gz && \
       cd /src && PATH=/gotool/go/bin:\$PATH GOTOOLCHAIN=local GOSUMDB=off \
       GOPROXY='file:///goproxy' HOME=/root go mod vendor"
  fi
fi

echo "== context ready: dl/ src/ vendor/ =="
