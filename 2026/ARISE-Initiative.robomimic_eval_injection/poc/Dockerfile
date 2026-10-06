FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HUB_OFFLINE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates libgl1 libglib2.0-0 libegl1 libgles2 libosmesa6 \
    && rm -rf /var/lib/apt/lists/*

# CPU-only PyTorch (upstream robomimic 0.5.0 declares torch + torchvision unpinned)
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \
        torch==2.4.1 torchvision==0.19.1

# Remaining runtime deps needed to import robomimic.utils.file_utils (see setup.py install_requires)
RUN pip install --no-cache-dir \
        "numpy==1.26.4" h5py psutil tqdm termcolor tensorboard tensorboardX \
        imageio imageio-ffmpeg matplotlib egl_probe \
        huggingface_hub==0.23.4 transformers==4.41.2 diffusers==0.11.1

# Vendored, commit-pinned robomimic source (PYTHONPATH import, not pip-installed)
COPY robomimic-src/ /work/robomimic-src/
ENV PYTHONPATH=/work/robomimic-src

# Fail the build early if the import surface is incomplete
RUN python -c "import robomimic, robomimic.utils.file_utils as F; print('robomimic import OK'); print('policy_from_checkpoint:', callable(F.policy_from_checkpoint))"

WORKDIR /work
