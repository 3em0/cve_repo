# Reproduction image for the Z-Image shard-path traversal
# (Tongyi-MAI/Z-Image @ 26f23eda626ffadda020b04ff79488e1d72004cd).
#
# The product source is the pinned-commit archive shipped next to this file, so the
# build needs no network access to GitHub. Dependencies follow the repository's own
# pyproject.toml (torch>=2.5.0, transformers>=4.51.0, safetensors, loguru, pillow,
# accelerate, huggingface_hub>=0.25.0); versions are resolved once at build time and
# printed by the `pip show` step of the PoC.
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# CPU-only torch keeps the image small; the loader path under test is device-agnostic.
RUN pip install --index-url https://download.pytorch.org/whl/cpu "torch==2.9.1+cpu"

RUN pip install transformers safetensors loguru pillow numpy accelerate huggingface_hub

COPY Z-Image-26f23ed.tar.gz /tmp/
RUN tar -xzf /tmp/Z-Image-26f23ed.tar.gz -C /opt \
    && mv /opt/Z-Image-26f23ed /opt/Z-Image \
    && rm /tmp/Z-Image-26f23ed.tar.gz

WORKDIR /work/poc
CMD ["sleep", "infinity"]
