# ColossalAI optimizer-checkpoint deserialization PoC environment.
#
# The finding lives in the async optimizer-checkpoint serializer that
# ColossalAI added for its ZeRO / Gemini plugins:
#
#   colossalai/utils/safetensors.py:35-38   _tensor_to_object()
#   colossalai/utils/safetensors.py:96-100  _unflatten_optim_state_dict()  <- key routing
#   colossalai/utils/safetensors.py:200-205 load_flat()                     <- public loader
#
# Why a container:
#   * ColossalAI is a Linux-first project (colossalai/__init__.py pulls in a
#     POSIX-only import chain), and the delivered artifact is an optimizer
#     checkpoint written on a training host, so a Linux filesystem is the
#     honest environment for this reproduction.
#   * ColossalAI's own async writer (save()/save_nested()/move_and_save()) needs
#     TensorNVMe, which is a CUDA extension and does not build in a CPU-only
#     container.  The PoC therefore writes the artifact with the product's own
#     serializer (colossalai.utils.safetensors.prepare()), which is the same
#     header + raw-tensor layout that save() emits; see make_poc.py.
#
#   docker build -t colossalai-deser-poc .
#   docker run --rm -it colossalai-deser-poc bash
FROM python:3.12-slim

ARG PIP_INDEX=https://pypi.org/simple
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/work/repo

# CPU-only torch wheels: the default PyPI wheel pulls several GB of nvidia-*
# packages that a CPU reproduction never touches.
RUN pip install --index-url ${TORCH_INDEX} torch

RUN pip install --index-url ${PIP_INDEX} "safetensors==0.8.0" numpy

# Import-time dependencies of the two product modules this PoC drives:
#   colossalai.utils.safetensors              -> torch, safetensors
#   colossalai.checkpoint_io.GeneralCheckpointIO -> psutil, peft
RUN pip install --index-url ${PIP_INDEX} psutil peft

WORKDIR /work

# Pinned upstream source, exported with `git archive` from the exact commit.
COPY colossalai-4f9953b.tar.gz /tmp/src.tar.gz
RUN mkdir -p /work/repo \
    && tar -xzf /tmp/src.tar.gz -C /work/repo --strip-components=1 \
    && rm /tmp/src.tar.gz

COPY PINNED_COMMIT.txt /work/PINNED_COMMIT.txt
COPY make_poc.py /work/make_poc.py
COPY run_load.py /work/run_load.py
COPY probe_flat.py /work/probe_flat.py
COPY outer_parser_control.py /work/outer_parser_control.py
