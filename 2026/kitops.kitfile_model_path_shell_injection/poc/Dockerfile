# mbe2e root: kitops.kitfile_model_path_shell_injection (seq 125)
# Real product: kitops-ml/kitops pinned at b6762849b23a599c834e5f14eda5cebcef40b640
#
# NOTE on .37: `apt-get` hangs inside containers, so the Go source is cloned and
# checked out ON THE HOST and COPYed in.  The pin is self-verified at run time by
# recomputing a deterministic digest of that tree (exp/treehash.py).
# proxy.golang.org is also unreachable from containers on .37, so the module
# graph is vendored ON THE HOST (`go mod vendor` at the pin) and copied in; the
# build itself is still done from the pinned source inside the container.
FROM golang:1.25-bookworm AS build
COPY src /src
COPY vendor /src/vendor
RUN cd /src \
 && CGO_ENABLED=0 GOFLAGS=-trimpath GOFLAGS="-mod=vendor -trimpath" go build -o /kit . \
 && /kit version

FROM mbe2e/base:py311
LABEL mbe2e="1"

ENV PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/root

COPY --from=build /kit /usr/local/bin/kit
COPY src /work/kitops
COPY example /work/example
COPY exp /work/exp

RUN kit version

# Provision the `kit dev` harness the way a first `kit dev start` does.
# `pkg/lib/harness/llm_download.go` fetches llamafile from https://jozu.ml/downloads/.
# If that host is reachable from the build network we let the product provision
# itself; otherwise we leave an inert placeholder so that `checkHarness()` is
# satisfied.  Either way the llamafile binary is DOWNSTREAM of the injection:
# the canary is executed by /bin/sh from the command string kitops itself builds
# (pkg/lib/harness/llm-harness.go:102), before llamafile would ever be exec'd.
RUN set -eu; \
    H="$HOME/.local/share/kitops/harness"; \
    mkdir -p /work/prov/models; \
    printf 'manifestVersion: "1.0.0"\npackage:\n  name: prov\n  version: 0.0.1\nmodel:\n  name: prov\n  path: models\n' > /work/prov/Kitfile; \
    : > /work/prov/models/prov.gguf; \
    (timeout 120 kit dev start /work/prov --port 18080 >/work/prov/provision.log 2>&1 || true); \
    (timeout 60 kit dev stop >>/work/prov/provision.log 2>&1 || true); \
    mkdir -p "$H/ui"; \
    if [ -s "$H/llamafile" ]; then echo "downloaded_by_product" > /work/harness_provenance.txt; \
    else printf '#!/bin/sh\nexit 127\n' > "$H/llamafile"; chmod +x "$H/llamafile"; \
         echo "inert_placeholder_jozu.ml_unreachable_from_container" > /work/harness_provenance.txt; fi; \
    printf '0.8.16' > "$H/llamafile.version"; \
    rm -f "$H/process.pid" "$H/harness.log"; \
    ls -la "$H"; cat /work/harness_provenance.txt

# the attacker's whole capability: three ModelKit context directories
RUN python /work/example/build_artifact.py /artifact && cat /artifact/SHA256SUMS

WORKDIR /work
CMD ["python", "/work/exp/drive.py"]
