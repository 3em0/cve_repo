# Reproduction image for showlab/Show-o @45a5a2de01d1 llm_model_path repo-redirect PoC.
# Base: vita-poc:35d064a6 (torch 2.3.1+cpu / torchvision 0.18.1+cpu on ubuntu 22.04;
# the CPU wheels index is unreachable from this network, so the CPU-torch base is reused).
# transformers is set to 4.47.0 - the pin of the repository's own show-o2/build_env.sh
# at this commit (top-level requirements.txt: transformers==4.41.1, also affected era).
FROM vita-poc:35d064a6

RUN python3 -m pip install --no-cache-dir --upgrade "transformers==4.47.0" \
        omegaconf jaxtyping typeguard einops sentencepiece "diffusers==0.31.0" "accelerate==0.23.0"

ENV PYTHONUNBUFFERED=1
WORKDIR /poc

# Pin-copy of showlab/Show-o@45a5a2de01d1 + drivers (never modified at runtime)
COPY . /poc
