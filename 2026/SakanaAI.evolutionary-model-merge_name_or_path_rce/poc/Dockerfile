# Reproduction environment for:
#   SakanaAI/evolutionary-model-merge @ 09aff543dd2ae966b3dfe457b750563ab063eb03
#   evomerge/modules/heron/video_blip/configuration_video_blip.py
#
# Versions follow the repository's own lockfile (poetry.lock):
#   python ^3.10 (pyproject.toml) -> 3.11 here
#   torch           2.1.2   (poetry.lock:3342)
#   transformers    4.38.2  (poetry.lock:3415)
#   tokenizers      0.15.2  (poetry.lock:3193)
#   safetensors     0.4.2   (poetry.lock:2904)
#   huggingface-hub 0.21.4  (poetry.lock:1045)
# numpy stays < 2 because torch 2.1.2 was built against the numpy 1.x ABI.
#
# CPU-only: the vulnerable path is pure config handling and needs no GPU.
FROM python:3.11-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/work/work/hf-cache

RUN pip install "numpy==1.26.4"
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch==2.1.2
# einops is one of the project's own dependencies (pyproject.toml: einops = "^0.7.0");
# transformers refuses to import a remote modeling file whose imports are missing.
RUN pip install transformers==4.38.2 tokenizers==0.15.2 safetensors==0.4.2 huggingface-hub==0.21.4 einops==0.7.0 "numpy==1.26.4"

WORKDIR /work
CMD ["bash"]
