# Equivalent container environment (Debian + CPython 3.7, the rasa_nlu era
# runtime) for the pinned-commit PoC. The primary capture on 2026-10-06 used
# the host route (CPython 3.12 venv, see run_repro.ps1); both run the same
# scripts and the same metadata-only model directories.
#
#   docker build -t rasanlu-reflection-poc .
#   docker run --rm -it -p 127.0.0.1:17766:17766 rasanlu-reflection-poc bash
#   # inside: python make_poc.py && (python -m http.server 17766 &) && \
#   #         python run_poc.py model_neg && python run_poc.py model_pos
FROM python:3.7-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-minimal.txt /tmp/requirements-minimal.txt
RUN pip install --no-cache-dir -r /tmp/requirements-minimal.txt

RUN git clone https://github.com/crownpku/Rasa_NLU_Chi.git /opt/Rasa_NLU_Chi \
    && git -C /opt/Rasa_NLU_Chi checkout f995c06e5aee5b6f68ea877c1a271667357a1c68 \
    && pip install --no-cache-dir --no-deps /opt/Rasa_NLU_Chi

WORKDIR /work
COPY make_poc.py run_poc.py show_code.py ./
