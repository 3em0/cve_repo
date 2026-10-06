# Reproduction environment for VITA-MLLM/VITA @ commit 35d064a6542a5d812136fcd66fa93d9beb27b03c
#
# Dependency pins follow the repository's own requirements.txt
# (torch==2.3.1, torchaudio==2.3.1, transformers==4.41.1); CPU wheels are used
# because the reproduction box has no GPU.
#
#  - flash_attn is simply absent: modeling_intern_vit.py falls back to plain
#    attention when the import fails (has_flash_attn = False).
#  - xformers has an unguarded module-level import in eva_vit.py, so a
#    non-functional import-only stub is provided at /opt/shims; neither module
#    is touched by the audio-encoder code path under test.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3.10 python3.10-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN python3.10 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir \
      torch==2.3.1+cpu torchaudio==2.3.1+cpu torchvision==0.18.1+cpu \
      --index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir \
      transformers==4.41.1 accelerate numpy==1.26.4 pyyaml pillow timm einops six

# Pinned vulnerable source: codeload tarball of the pinned commit
COPY VITA-35d064a6542a.tar.gz /tmp/VITA.tar.gz
RUN mkdir -p /opt/VITA \
 && tar xzf /tmp/VITA.tar.gz -C /opt/VITA --strip-components=1 \
 && rm /tmp/VITA.tar.gz

# Import-only stub so `import xformers.ops` succeeds on a CPU-only box
COPY xformers_stub/xformers /opt/shims/xformers

# PoC scripts and benign inputs (legitimate second-repo data files + tokenizer)
COPY make_poc.py mock_hf_server.py run_driver.py /work/poc/
COPY inputs/train.yaml inputs/global_cmvn /work/poc/inputs/
COPY inputs/tokenizer /work/poc/inputs/tokenizer/

ENV PYTHONPATH="/opt/shims:/opt/VITA"
WORKDIR /work/poc
CMD ["sleep", "infinity"]
