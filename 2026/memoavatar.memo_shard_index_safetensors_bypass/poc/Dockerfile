# Reproduction environment for memoavatar/memo @ commit 151b02438f0b
#
# Dependency pins follow the repository's own pyproject.toml
# (torch==2.5.1, diffusers==0.31.0, accelerate==1.1.1, transformers==4.46.3,
#  huggingface-hub==0.26.2, numpy==1.26.4, einops==0.8.0); CPU wheels are used
# because the reproduction box has no GPU. The pipeline loader under test
# (diffusers UNet2DConditionModel.from_pretrained) is unaffected by the CUDA
# vs CPU wheel choice.
#
# The PoC model packages are built inside the container by make_poc.py; no
# network access is needed at load time (the model root is a local directory).
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3.10 python3.10-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN python3.10 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir torch==2.5.1 --index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir \
      diffusers==0.31.0 accelerate==1.1.1 transformers==4.46.3 \
      huggingface-hub==0.26.2 safetensors numpy==1.26.4 einops==0.8.0 pillow

# Pinned vulnerable source: codeload tarball of commit 151b02438f0b
COPY memo-151b02438f0b.tar.gz /tmp/memo.tar.gz
RUN mkdir -p /opt/memo \
 && tar xzf /tmp/memo.tar.gz -C /opt/memo --strip-components=1 \
 && rm /tmp/memo.tar.gz

# PoC scripts
COPY make_poc.py run_poc.py /work/poc/

WORKDIR /work/poc
CMD ["sleep", "infinity"]
