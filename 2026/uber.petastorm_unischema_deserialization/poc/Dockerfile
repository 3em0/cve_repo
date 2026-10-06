# Reproducer image for the petastorm `dataset-toolkit.unischema.v1` unpickling RCE.
#
# petastorm 0.13.1 / commit 01ba9cb7da8d, Ubuntu 22.04 + Python 3.10 + pyarrow 8.0.0.
# pyarrow 8 is used because it still provides `pyarrow.parquet.ParquetDatasetPiece`
# and `ParquetDataset.metadata_path`, which petastorm's row-group loader relies on.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
# pyarrow 8 still ships the legacy ParquetDataset API that petastorm 0.13.1 uses, and
# annotates every use with a FutureWarning. Those deprecation notices are unrelated to
# the vulnerability and would bury the PoC output, so they are muted for readability.
ENV PYTHONWARNINGS=ignore::FutureWarning

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/bin/python3 /usr/local/bin/python

RUN python -m pip install --no-cache-dir --upgrade "pip<24" "setuptools<70" wheel

# petastorm's declared runtime dependency set (setup.py), pinned to the versions of
# the vulnerable commit's era. Pip is given generous retries: the pyspark wheel is
# ~317 MB and slow links time out on the default settings.
ARG PIP_FLAGS="--no-cache-dir --retries 10 --timeout 120"
RUN python -m pip install ${PIP_FLAGS} \
      "pyarrow==8.0.0" \
      "pandas==1.5.3" \
      "numpy==1.24.4" \
      "six>=1.5.0" \
      "dill>=0.2.1" \
      "diskcache>=3.0.0" \
      "future>=0.10.2" \
      "packaging>=15.0" \
      "psutil>=4.0.0" \
      "pyzmq>=14.0.0" \
      "fsspec"

# pyspark is only needed for its sql type classes (the pickled Unischema of a real
# petastorm dataset references them); Spark itself is never started. It ships as a
# ~300 MB sdist, so this layer is kept separate and can be pointed at a closer mirror:
#   docker build --build-arg PIP_INDEX="-i https://pypi.tuna.tsinghua.edu.cn/simple" ...
ARG PIP_INDEX=""
RUN python -m pip install ${PIP_FLAGS} ${PIP_INDEX} "pyspark==3.5.1"

# The pinned, unmodified upstream source of the vulnerable commit.
COPY petastorm-01ba9cb7 /opt/petastorm-01ba9cb7
RUN python -m pip install --no-cache-dir --no-deps /opt/petastorm-01ba9cb7

WORKDIR /poc
COPY make_poc.py read_dataset.py /poc/
