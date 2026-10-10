FROM python:3.12-slim

# libgomp1 is required by the torch cpu wheels; the slim image does not ship it
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 diffutils \
    && rm -rf /var/lib/apt/lists/*

# Era-matched dependency set for ThunderKittens demos/based at cb21f34:
# torch/torchvision cpu, transformers 4.40.0 (the generation API this demo
# imports), hydra-core 1.3.2 (the dispatch engine in gpt.py), einops, triton
# (the no-flash-attn RMSNorm fallback that gpt.py falls back to).
RUN pip install --no-cache-dir torch torchvision --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir "numpy<2" "transformers==4.40.0" "hydra-core==1.3.2" einops triton

# non-root victim user, uid/gid 1000 to match the host user on the bind mount
RUN useradd -m -u 1000 victim
USER victim
WORKDIR /work
