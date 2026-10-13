# diff-svc 236de77 — unsafe reflection dispatch PoC environment.
#
# Why a container instead of the host:
#   * network/vocoders/pwg.py selects its checkpoint with a forward-slash regex
#     applied to glob() output, so the PWG sample only reproduces on a POSIX
#     filesystem (on Windows glob() returns `dir\file` and the regex never
#     matches).  The vulnerable dispatch itself is OS independent.
#   * modules/parallel_wavegan/layers/pqmf.py imports scipy.signal.kaiser, which
#     was removed in SciPy 1.13, so the era-appropriate scipy<1.13 pin is needed
#     (the repo's own requirements.txt pins scipy==1.9.3).
#   * python:3.12 is the newest interpreter that still has scipy 1.12 wheels.
#
#   docker build -t diffsvc-poc .
#   docker run --rm -it diffsvc-poc bash
FROM python:3.12-slim

ARG PIP_INDEX=https://pypi.org/simple
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

# CPU-only torch wheels: the default PyPI wheels pull several GB of nvidia-*
# packages that this CPU reproduction never touches. torchaudio is required by
# preprocessing/data_gen_utils.py -> torchcrepe.
RUN pip install --index-url ${TORCH_INDEX} torch torchaudio

RUN pip install --index-url ${PIP_INDEX} \
        "numpy<2" "scipy==1.12.0" "numba==0.61.2" PyYAML \
        "librosa==0.10.2.post1" "pytorch_lightning==2.6.6" tensorboard \
        h5py praat-parselmouth scikit-image scikit-learn matplotlib \
        soundfile einops tqdm

# --no-deps: pycwt publishes a numpy>=2 requirement that contradicts the
# scipy 1.12 pin above; the other four only need packages already installed.
RUN pip install --index-url ${PIP_INDEX} --no-deps \
        pycwt resampy torchcrepe webrtcvad-wheels pyloudnorm

WORKDIR /work

COPY diff-svc-236de77.tar.gz /tmp/src.tar.gz
RUN mkdir -p /work/repo \
    && tar -xzf /tmp/src.tar.gz -C /work/repo --strip-components=1 \
    && rm /tmp/src.tar.gz

COPY PINNED_COMMIT.txt /work/PINNED_COMMIT.txt
COPY make_poc.py /work/make_poc.py
