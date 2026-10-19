#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HumanMLLM/R1-Omni (pinned commit 17cafcae0b0a1c454896f4eb7a1c006bf13e1f4d)
Directed model load -- AUDIO path.

REPRODUCTION DRIVER -- drives the real, unmodified loader of one arm:

    python run_repro.py redirected   # /models/humanomni-redirected -> /artifacts/whisper-redirected
    python run_repro.py trusted      # /models/humanomni-trusted    -> /artifacts/whisper-trusted

Both arms run the same upstream code:

  inference.py:28                              model_init(model_path)
  humanomni/__init__.py:19                     load_pretrained_model(model_path, None, model_name)
  humanomni/model/__init__.py:66               AutoConfig.from_pretrained(model_path)   <- safe JSON
  humanomni/model/humanomni_arch.py:94-97      build_audio_tower(config, delay_load=True)
                                               -> WhisperConfig.from_pretrained(<field>)  (1st read)
                                               -> build_audio_projector(config, ...)
  humanomni/model/__init__.py:99               audio_tower.load_model()                 <- the sink
  humanomni/model/encoder.py:195-196           WhisperFeatureExtractor.from_pretrained(<field>)
                                               WhisperForAudioClassification.from_pretrained(<field>)
  humanomni/model/__init__.py:100,102-103      audio_tower.to(cpu, fp16); audio_processor returned

`load_pretrained_model` is called with device="cpu" because `model_init` hardcodes
device="cuda"; the vulnerable read at humanomni/model/__init__.py:99 is reached
identically (it happens before the tower is moved to a device).
"""

import json
import os
import sys
import traceback
from pathlib import Path

sys.dont_write_bytecode = True          # keep the pinned source copy pristine

POC = Path(__file__).resolve().parent
SRC = POC / "R1-Omni-17cafca"
PACKAGES = {"redirected": Path("/models/humanomni-redirected"),
            "trusted": Path("/models/humanomni-trusted")}
WHISPERS = {"redirected": Path("/artifacts/whisper-redirected"),
            "trusted": Path("/artifacts/whisper-trusted")}
MARK_POS_EXPECTED = "AUDIO-REDIRECTED-ARM"
MARK_NEG_EXPECTED = "AUDIO-TRUSTED-CONTROL-ARM"

ARM = sys.argv[1] if len(sys.argv) > 1 else "redirected"
if ARM not in PACKAGES:
    sys.exit(f"usage: {sys.argv[0]} [redirected|trusted]")
PKG = PACKAGES[ARM]
OTHER = "trusted" if ARM == "redirected" else "redirected"

# Mirror the environment the repository's own entry point sets (inference.py:8).
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_HUB_OFFLINE"] = "1"

LINE = "-" * 74

# ---------------------------------------------------------------------------
# record every path the process touches below the artifact and the fixture roots
# ---------------------------------------------------------------------------
WATCH = ("/models", "/artifacts", "/mnt/data/jiaxing.zjx")
reads = {}


def _hook(event, args):
    if event in ("open", "os.stat", "os.listdir", "os.scandir") and args:
        target = args[0]
        if isinstance(target, (str, bytes, os.PathLike)):
            text = os.fsdecode(target)
            if text.startswith(WATCH):
                reads.setdefault(text, event)


sys.addaudithook(_hook)


def watched(prefix):
    return sorted(p for p in reads if p == str(prefix) or p.startswith(str(prefix) + "/"))


def opened_files(prefix):
    return sorted({p for p in watched(prefix) if os.path.isfile(p)})


def main():
    print("=" * 74)
    print(f"R1-Omni / HumanOmni AUDIO directed model load -- {ARM.upper()} arm")
    print("=" * 74)
    print(f"pinned source   : {SRC}")
    print(f"victim loads    : {PKG}   (python inference.py --model_path {PKG})")

    pkg = json.loads((PKG / "config.json").read_text(encoding="utf-8"))
    field = pkg["mm_audio_tower"]
    print(f"package field   : mm_audio_tower = {field!r}")
    print(f"                  that is the {ARM} Whisper directory (the other arm names "
          f"{WHISPERS[OTHER]})")
    print()

    sys.path.insert(0, str(SRC))
    import torch
    from humanomni.model import load_pretrained_model

    print(LINE)
    print("loading through the real upstream loader (no patching, no stubs)")
    print(LINE)
    try:
        tokenizer, model, processor, context_len, audio_processor = load_pretrained_model(
            str(PKG), None, "HumanOmni_7B", device_map="cpu", device="cpu")
    except Exception:
        print("load_pretrained_model raised:")
        traceback.print_exc()
        return 2

    tower = model.get_audio_tower()
    cfg = tower.audio_tower.config
    resolved = str(getattr(cfg, "_name_or_path", "?"))
    bias = tower.audio_tower.encoder.conv1.bias
    bias_mean = float(bias.detach().float().mean())

    print("load_pretrained_model: OK")
    print(f"  tokenizer            : {type(tokenizer).__name__}")
    print(f"  model.config.model_type: {model.config.model_type}")
    print(f"  context_len          : {context_len}")
    print(f"  audio_processor      : {type(audio_processor).__name__}")
    print()
    print(LINE)
    print("what the loader actually read for the audio model")
    print(LINE)
    print(f"  wrapper class chosen : {type(tower).__name__}   (encoder.py:250, substring 'whisper')")
    print(f"  raw field value      : {tower.audio_tower_name}")
    print(f"  resolved directory   : {resolved}")
    print(f"  whisper config marker: {getattr(cfg, 'poc_arm_marker', None)!r}")
    print(f"  classifier_dropout   : {getattr(cfg, 'classifier_dropout', None)}")
    print(f"  num_labels / d_model : {getattr(cfg, 'num_labels', None)} / {getattr(cfg, 'd_model', None)}")
    print(f"  weight marker        : encoder.conv1.bias mean = {bias_mean:+.6f}")
    print(f"  processor is the one returned: {audio_processor is tower.audio_processor}")
    print(f"  processor marker     : {getattr(audio_processor, 'poc_arm_marker', None)!r}")
    print(f"  processor sampling   : {getattr(audio_processor, 'sampling_rate', None)} Hz, "
          f"feature_size {getattr(audio_processor, 'feature_size', None)}")
    print()
    print("  contents of the directory the loader resolved:")
    for name in sorted(os.listdir(resolved)):
        full = os.path.join(resolved, name)
        print(f"      {name}  ({os.path.getsize(full)} bytes)")

    from safetensors import safe_open
    with safe_open(os.path.join(resolved, "model.safetensors"), framework="pt") as fh:
        tensor_keys = list(fh.keys())
    exclusive = [k for k in tensor_keys if k.endswith("_marker")]
    print(f"  tensors in the resolved weights file: {len(tensor_keys)}")
    print(f"  arm-exclusive weight markers in it  : {exclusive}")
    print()

    print(LINE)
    print("filesystem reads recorded under the two candidate directories")
    print(LINE)
    for label, root in ((f"THIS arm's target  {WHISPERS[ARM]}", WHISPERS[ARM]),
                        (f"the other arm's    {WHISPERS[OTHER]}", WHISPERS[OTHER])):
        files = opened_files(root)
        print(f"  {label}")
        print(f"      paths touched : {len(watched(root))}")
        print(f"      files opened  : {len(files)}  "
              f"{[os.path.relpath(p, str(root)) for p in files]}")
    pkg_files = opened_files(PKG)
    print(f"  the package itself   {PKG}")
    print(f"      files opened  : {len(pkg_files)}  "
          f"{[os.path.relpath(p, str(PKG)) for p in pkg_files]}")
    print()

    # -----------------------------------------------------------------------
    # the loaded (attacker-chosen) audio model is really used: feature extraction
    # with the loaded processor, then an encoder forward pass
    # -----------------------------------------------------------------------
    print(LINE)
    print("audio inference with the loaded (package-chosen) audio model")
    print(LINE)
    # a deterministic 30 s waveform (Whisper's native window), so the whole mel
    # input is signal and the two arms' substituted weights show up in the result
    wave = torch.randn(int(16000 * 30), generator=torch.Generator().manual_seed(20261013)) * 0.1
    feats = audio_processor(wave, sampling_rate=16000, return_tensors="pt")
    mel = feats["input_features"]
    print(f"  processor output     : input_features {tuple(mel.shape)}")
    try:
        with torch.no_grad():
            out = tower(mel.to(dtype=tower.dtype))
        how = f"dtype {tower.dtype}"
    except Exception as exc:                                   # noqa: BLE001
        print(f"  forward in {tower.dtype} failed ({type(exc).__name__}: {exc}); retrying in float32")
        tower.float()
        with torch.no_grad():
            out = tower(mel.float())
        how = f"float32 fallback (original dtype {tower.dtype} unsupported on this CPU build)"
    print(f"  encoder output       : {tuple(out.shape)}   ({how})")
    print(f"  output mean          : {float(out.float().mean()):+.8f}")
    print()

    print(LINE)
    print(f"EVIDENCE SUMMARY ({ARM} arm)")
    print(LINE)
    marker = getattr(cfg, "poc_arm_marker", None)
    print(f"  victim loads the package        : {PKG}")
    print("  loader driven                   : humanomni.model.load_pretrained_model")
    print("                                    (pinned upstream copy, unmodified)")
    print(f"  package field mm_audio_tower    : {field}")
    print(f"  wrapper chosen by encoder.py    : {type(tower).__name__}  ('whisper' substring)")
    print(f"  directory actually loaded       : {resolved}")
    print(f"  config marker read              : {marker}")
    print(f"  classifier_dropout read         : {getattr(cfg, 'classifier_dropout', None)}")
    print(f"  weight marker (conv1.bias mean) : {bias_mean:+.6f}")
    print(f"  arm-exclusive tensors in file   : {exclusive}")
    print(f"  audio processor from that dir   : {type(audio_processor).__name__} "
          f"(marker {getattr(audio_processor, 'poc_arm_marker', None)})")
    print(f"  files opened in its directory   : {len(opened_files(WHISPERS[ARM]))}")
    print(f"  files opened in the other one   : {len(opened_files(WHISPERS[OTHER]))}")
    print(f"  audio inference                 : 30 s waveform -> mel {tuple(mel.shape)} "
          f"-> {tuple(out.shape)}  (output mean {float(out.float().mean()):+.8f})")
    print(LINE)
    if ARM == "redirected":
        if marker == MARK_POS_EXPECTED and resolved == str(WHISPERS["redirected"]):
            print("  RESULT: AUDIO MODEL LOADED FROM THE REDIRECTED ARTIFACT")
            print("          the package field decides the source; no boundary check,")
            print("          no warning, the call returns normally")
        else:
            print(f"  UNEXPECTED: marker={marker!r} resolved={resolved!r}")
            return 3
    else:
        if marker == MARK_NEG_EXPECTED and resolved == str(WHISPERS["trusted"]):
            print("  RESULT: control arm loaded the TRUSTED audio model and completed")
            print("          inference -- the single field decides which one is used")
        else:
            print(f"  UNEXPECTED: marker={marker!r} resolved={resolved!r}")
            return 3
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())