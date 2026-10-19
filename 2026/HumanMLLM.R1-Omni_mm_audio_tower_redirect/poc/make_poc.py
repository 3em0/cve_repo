#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HumanMLLM/R1-Omni (pinned commit 17cafcae0b0a1c454896f4eb7a1c006bf13e1f4d)
Directed model load -- AUDIO path: `mm_audio_tower` -> WhisperAudioTower.load_model()
(humanomni/model/encoder.py:191-198, the reuse at 195-196; field stored at 180;
 dispatch by substring at encoder.py:250).

ARTIFACT BUILDER -- run once before run_repro.py.

Builds everything from scratch and deterministically:

  /models/humanomni-redirected/          main HumanOmni package (positive artefact)
      config.json                        mm_audio_tower = "/artifacts/whisper-redirected"
      model.safetensors, generation_config.json, tokenizer files
      siglip-vision/                     in-package vision tower (identical in both arms)

  /models/humanomni-trusted/             control package: same bytes, ONE field differs
      config.json                        mm_audio_tower = "/artifacts/whisper-trusted"

  /artifacts/whisper-redirected/         data-only Whisper model the package redirects to
  /artifacts/whisper-trusted/            data-only Whisper model of the trusted control
      config.json, preprocessor_config.json, model.safetensors

  /mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V/bert-base-uncased/
      tiny BERT stand-in for the absolute path hardcoded at
      humanomni/model/humanomni_arch.py:83-85 (the loader cannot run without it)

Both Whisper directories have exactly the same architecture and differ only in
plain data markers (a config string, a dropout value, a bias value, one
arm-exclusive tensor), so the observed outcome identifies which directory the
loader read.  There is no .py, no plugin, no shell script and no pickle anywhere
in either second-model directory: both are pure data.

Nothing here executes code and nothing contacts the network.
"""

import hashlib
import json
import shutil
import sys

sys.dont_write_bytecode = True          # keep the pinned source copy pristine

from pathlib import Path

POC_DIR = Path(__file__).resolve().parent
SRC_DIR = POC_DIR / "R1-Omni-17cafca"      # pinned, unmodified upstream copy
WORK = POC_DIR / "work"

MODELS = Path("/models")
PKG_POS = MODELS / "humanomni-redirected"     # positive arm's main package
PKG_NEG = MODELS / "humanomni-trusted"        # negative arm's main package
ARTIFACTS = Path("/artifacts")
WHISPER_POS = ARTIFACTS / "whisper-redirected"
WHISPER_NEG = ARTIFACTS / "whisper-trusted"
BERT_DIR = Path("/mnt/data/jiaxing.zjx/code/R1-V-Qwen/R1-V/bert-base-uncased")

# The only value that differs between the two arms:
FIELD_POS = str(WHISPER_POS)
FIELD_NEG = str(WHISPER_NEG)

# Plain data markers used to observe which second-model directory was read.
MARK_POS = "AUDIO-REDIRECTED-ARM"
MARK_NEG = "AUDIO-TRUSTED-CONTROL-ARM"
DROPOUT_POS = 0.11
DROPOUT_NEG = 0.77
BIAS_POS = 0.125        # encoder.conv1.bias value in the redirected directory
BIAS_NEG = -0.375       # encoder.conv1.bias value in the trusted directory
EXCL_POS = "poc_redirected_audio_arm_only_weight_marker"
EXCL_NEG = "poc_trusted_audio_arm_only_weight_marker"

VISION_KW = dict(hidden_size=32, intermediate_size=64, num_hidden_layers=2,
                 num_attention_heads=4, image_size=32, patch_size=8, num_channels=3)
WHISPER_KW = dict(vocab_size=128, num_mel_bins=80, d_model=32, encoder_layers=2,
                  encoder_attention_heads=4, decoder_layers=2, decoder_attention_heads=4,
                  max_source_positions=1500, max_target_positions=64,
                  classifier_proj_size=32, num_labels=4)

HEAD = "=" * 74


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def tree(root, indent="    "):
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        out.append(f"{indent}{rel}/" if p.is_dir() else f"{indent}{rel}  ({p.stat().st_size} bytes)")
    return out


def fresh(path):
    """Empty a directory.  /models and /artifacts live directly under /, whose parent
    is not writable, so the directory itself is kept and only its contents go."""
    if path.exists():
        for child in path.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)


def check_writable(path):
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("ok")
        probe.unlink()
    except Exception as exc:                                  # noqa: BLE001
        sys.exit(f"FATAL: cannot write {path} ({exc}).\nRun poc/setup_fixtures.sh first.")


# --------------------------------------------------------------------------
# 1. tiny BERT stand-in for the path hardcoded in humanomni_arch.py:83-85
# --------------------------------------------------------------------------
def build_bert_fixture():
    from transformers import BertConfig, BertModel, BertTokenizer

    if (BERT_DIR / "config.json").exists():
        print(f"[1] bert fixture already present at {BERT_DIR}")
        return

    try:
        BERT_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:                                  # noqa: BLE001
        sys.exit(f"FATAL: cannot create {BERT_DIR} ({exc}).\nRun poc/setup_fixtures.sh first.")
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + [chr(c) for c in range(ord("a"), ord("z") + 1)]
    (BERT_DIR / "vocab.txt").write_text("\n".join(vocab) + "\n", encoding="utf-8")
    cfg = BertConfig(vocab_size=len(vocab), hidden_size=32, num_hidden_layers=1,
                     num_attention_heads=4, intermediate_size=32, max_position_embeddings=64)
    BertModel(cfg).save_pretrained(BERT_DIR)
    BertTokenizer(vocab_file=str(BERT_DIR / "vocab.txt"), do_lower_case=True).save_pretrained(BERT_DIR)
    print(f"[1] wrote tiny BERT stand-in to {BERT_DIR} (hidden_size=32, 1 layer)")


# --------------------------------------------------------------------------
# 2. the two data-only Whisper audio-model directories
# --------------------------------------------------------------------------
def build_whisper(dest, marker, bias_value, exclusive_key, dropout):
    import torch
    from safetensors.torch import save_file
    from transformers import (WhisperConfig, WhisperFeatureExtractor,
                             WhisperForAudioClassification)

    fresh(dest)

    cfg = WhisperConfig(**WHISPER_KW)
    cfg.poc_arm_marker = marker          # plain config marker (data only)
    cfg.classifier_dropout = dropout     # plain parameter difference (no shape change)

    torch.manual_seed(606)               # deterministic weights
    model = WhisperForAudioClassification(cfg)
    with torch.no_grad():
        model.encoder.conv1.bias.fill_(bias_value)

    state = {k: v.contiguous() for k, v in model.state_dict().items()}
    state[exclusive_key] = torch.tensor([bias_value, 1.0])   # arm-exclusive weight marker
    save_file(state, str(dest / "model.safetensors"))
    cfg.to_json_file(str(dest / "config.json"))

    fe = WhisperFeatureExtractor(feature_size=WHISPER_KW["num_mel_bins"], sampling_rate=16000,
                                 hop_length=160, chunk_length=30, n_fft=400, padding_value=0.0)
    fe.poc_arm_marker = marker
    fe.save_pretrained(dest)

    print(f"[2] {dest}")
    print(f"      poc_arm_marker={marker!r}  classifier_dropout={dropout}  "
          f"conv1.bias={bias_value}")
    print(f"      exclusive tensor={exclusive_key}")
    print(f"      whisper params={sum(p.numel() for p in model.parameters())}")


# --------------------------------------------------------------------------
# 3. the main HumanOmni package (the first hop)
# --------------------------------------------------------------------------
def build_vision_tower(dest):
    import torch
    from safetensors.torch import save_file
    from transformers import SiglipImageProcessor, SiglipVisionConfig, SiglipVisionModel

    fresh(dest)
    cfg = SiglipVisionConfig(**VISION_KW)
    torch.manual_seed(4242)
    model = SiglipVisionModel(cfg)
    save_file({k: v.contiguous() for k, v in model.state_dict().items()},
              str(dest / "model.safetensors"))
    cfg.to_json_file(str(dest / "config.json"))
    SiglipImageProcessor(size={"height": 32, "width": 32},
                         image_mean=[0.5, 0.5, 0.5], image_std=[0.5, 0.5, 0.5]).save_pretrained(dest)
    print(f"[3] in-package vision tower {dest} ({sum(p.numel() for p in model.parameters())} params)")


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
    dump = json.loads(tk.to_str())
    vocab_file.write_text(json.dumps(dump["model"]["vocab"], ensure_ascii=False), encoding="utf-8")
    merges_file.write_text("\n".join(" ".join(m) for m in dump["model"]["merges"]) + "\n",
                           encoding="utf-8")
    tok = Qwen2Tokenizer(vocab_file=str(vocab_file), merges_file=str(merges_file),
                         unk_token="<|endoftext|>", eos_token="<|endoftext|>",
                         bos_token=None, pad_token=None, model_max_length=128)
    tok.save_pretrained(dest)


def build_main_package():
    sys.path.insert(0, str(SRC_DIR))
    import torch
    from humanomni.model.humanomni_model import (HumanOmniQwen2Config,
                                                 HumanOmniQwen2ForCausalLM)

    fresh(PKG_POS)
    build_vision_tower(PKG_POS / "siglip-vision")

    cfg = HumanOmniQwen2Config(
        vocab_size=256, hidden_size=64, intermediate_size=128, num_hidden_layers=2,
        num_attention_heads=4, num_key_value_heads=4, max_position_embeddings=128,
        tie_word_embeddings=False, torch_dtype="float32",
        # ---- the attacker-controlled field -------------------------------------
        mm_audio_tower=FIELD_POS,
        # ------------------------------------------------------------------------
        mm_vision_tower=str(PKG_POS / "siglip-vision"),   # in-package, same in both arms
        mm_projector_type="linear", mm_hidden_size=VISION_KW["hidden_size"],
        mm_vision_select_layer=-2, mm_vision_select_feature="patch",
        mm_use_x_start_end=False, num_frames=4,
    )

    torch.manual_seed(1713)
    model = HumanOmniQwen2ForCausalLM(cfg)
    params = sum(p.numel() for p in model.parameters())

    model.save_pretrained(PKG_POS)
    build_tokenizer(PKG_POS)
    print(f"[4] wrote main package {PKG_POS} (tiny stand-in: {params} params, "
          f"{cfg.num_hidden_layers} qwen2 layers, hidden {cfg.hidden_size}, "
          f"audio tower {cfg.mm_audio_tower})")


# --------------------------------------------------------------------------
# 4. positive / negative packages + hashes
# --------------------------------------------------------------------------
def build_control_package():
    fresh(PKG_NEG)
    for src in sorted(PKG_POS.rglob("*")):
        dst = PKG_NEG / src.relative_to(PKG_POS)
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
        else:
            shutil.copy2(src, dst)

    cfg_path = PKG_NEG / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert cfg["mm_audio_tower"] == FIELD_POS
    # the in-package vision tower must follow the package directory (it is the same
    # artifact, just at a different path) -- this is NOT the field under test
    cfg["mm_vision_tower"] = str(PKG_NEG / "siglip-vision")
    cfg["mm_audio_tower"] = FIELD_NEG
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(f"[5] wrote control package {PKG_NEG} (same files, one field changed)")


def diff_packages():
    files = sorted({p.relative_to(PKG_POS).as_posix() for p in PKG_POS.rglob("*") if p.is_file()} |
                   {p.relative_to(PKG_NEG).as_posix() for p in PKG_NEG.rglob("*") if p.is_file()})
    return [(rel, "IDENTICAL" if (PKG_POS / rel).is_file() and (PKG_NEG / rel).is_file()
             and sha256(PKG_POS / rel) == sha256(PKG_NEG / rel) else "DIFFERS") for rel in files]


def main():
    print(HEAD)
    print("R1-Omni / HumanOmni directed model load -- AUDIO arm (mm_audio_tower)")
    print(f"pinned source : {SRC_DIR}")
    print(HEAD)

    for p in (PKG_POS, PKG_NEG, WHISPER_POS, WHISPER_NEG):
        check_writable(p)
    WORK.mkdir(parents=True, exist_ok=True)

    build_bert_fixture()
    build_whisper(WHISPER_POS, MARK_POS, BIAS_POS, EXCL_POS, DROPOUT_POS)
    build_whisper(WHISPER_NEG, MARK_NEG, BIAS_NEG, EXCL_NEG, DROPOUT_NEG)
    build_main_package()
    build_control_package()

    pos_field = json.loads((PKG_POS / "config.json").read_text(encoding="utf-8"))["mm_audio_tower"]
    neg_field = json.loads((PKG_NEG / "config.json").read_text(encoding="utf-8"))["mm_audio_tower"]

    print()
    print(HEAD)
    print("ARTIFACT LAYOUT")
    print(HEAD)
    for root in (PKG_POS, PKG_NEG, WHISPER_POS, WHISPER_NEG):
        print(f"{root}/")
        for line in tree(root):
            print(line)
        print()

    print(HEAD)
    print("THE ONE FIELD THAT DIFFERS  (humanomni/model/encoder.py:248 -> :250)")
    print(HEAD)
    print(f"  {PKG_POS}/config.json")
    print(f"      mm_audio_tower = {pos_field}")
    print(f"      outside the package? {not pos_field.startswith(str(PKG_POS) + '/')}")
    print(f"  {PKG_NEG}/config.json")
    print(f"      mm_audio_tower = {neg_field}")
    print(f"      outside the package? {not neg_field.startswith(str(PKG_NEG) + '/')}")
    print()
    print("arm markers (plain data, used to observe which directory was read):")
    for root, mark, bias, excl, drop in ((WHISPER_POS, MARK_POS, BIAS_POS, EXCL_POS, DROPOUT_POS),
                                         (WHISPER_NEG, MARK_NEG, BIAS_NEG, EXCL_NEG, DROPOUT_NEG)):
        print(f"  {root}")
        print(f"      marker={mark}  classifier_dropout={drop}  "
              f"encoder.conv1.bias={bias}  tensor={excl}")

    print()
    print(HEAD)
    print("PACKAGE DIFF (positive vs control)")
    print(HEAD)
    for rel, status in diff_packages():
        print(f"  {status:<10} {rel}")
    a = json.loads((PKG_POS / "config.json").read_text(encoding="utf-8"))
    b = json.loads((PKG_NEG / "config.json").read_text(encoding="utf-8"))
    changed = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    print(f"  changed config.json keys: {changed}")
    print(f"    -> {[(k, a.get(k), b.get(k)) for k in changed]}")

    print()
    print(HEAD)
    print("SECOND-MODEL DIRECTORIES CONTAIN PURE DATA ONLY")
    print(HEAD)
    for root in (WHISPER_POS, WHISPER_NEG):
        names = sorted(p.name for p in root.rglob("*") if p.is_file())
        bad = [n for n in names if n.endswith((".py", ".pkl", ".pickle", ".so", ".sh", ".bin"))]
        print(f"  {root}: {names}")
        print(f"    program sidecars: {bad if bad else 'none'}")

    print()
    print(HEAD)
    print("SHA256SUMS")
    print(HEAD)
    lines = []
    for root in (PKG_POS, PKG_NEG, WHISPER_POS, WHISPER_NEG):
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
    print(f"  package (positive)  : {PKG_POS} -> mm_audio_tower = {pos_field}")
    print("                        OUTSIDE the package")
    print(f"  package (control)   : {PKG_NEG} -> mm_audio_tower = {neg_field}")
    print("                        OUTSIDE the package, but a trusted directory")
    print("  package diff        : only config.json differs")
    print("                        changed key(s): mm_audio_tower (plus the package's own")
    print("                        in-package mm_vision_tower path, not under test)")
    print("  whisper architecture: identical (each arm: same shapes, same param count)")
    print(f"    redirected arm    : marker={MARK_POS} dropout={DROPOUT_POS} bias={BIAS_POS}")
    print(f"    trusted arm       : marker={MARK_NEG} dropout={DROPOUT_NEG} bias={BIAS_NEG}")
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
