# Primary reproduction environment — the RELEASED product stack.
#
# `pip install ltp` resolves to ltp 4.2.14 + ltp_core 0.1.4 + ltp_extension 0.1.13
# from PyPI. ltp_core 0.1.4 (uploaded 2023-01-04) still re-exports the
# instantiate() helper from ltp_core/models/utils/__init__.py, so the neural
# inference path really reaches it.
#
# No apt-get: this build host cannot reach the Debian mirrors, and nothing
# outside pip is needed.
FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

# CPU-only torch keeps the image small; the vulnerable path needs no GPU.
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch

# Released artifacts, pinned to the versions `pip install ltp` resolves to.
RUN pip install \
      ltp==4.2.14 \
      ltp_core==0.1.4 \
      ltp_extension==0.1.13 \
      transformers \
      huggingface_hub

# Unprivileged user; /out is the directory the PoC writes its marker into.
RUN useradd -m -u 1000 poc \
 && mkdir -p /out /work \
 && chown -R poc:poc /out /work

COPY --chown=poc:poc . /work
WORKDIR /work
USER poc

CMD ["bash"]
