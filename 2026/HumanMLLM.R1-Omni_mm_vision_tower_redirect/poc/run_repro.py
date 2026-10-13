#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HumanMLLM/R1-Omni (pinned commit 17cafcae0b0a1c454896f4eb7a1c006bf13e1f4d)
Directed model load via the model package's `mm_vision_tower` string.

REPRODUCTION DRIVER -- drives the real, unmodified loader of one arm:

    python run_repro.py positive     # /model          -> /external/siglip-positive-canary
    python run_repro.py negative     # /model-negative -> /model-negative/siglip-vision

Both arms run the same upstream code:

  inference.py:28                        model_init(model_path)
  humanomni/__init__.py:19               load_pretrained_model(model_path, None, model_name)
  humanomni/model/__init__.py:66         AutoConfig.from_pretrained(model_path)   <- safe JSON
  humanomni/model/humanomni_arch.py:77   build_vision_tower(config, delay_load=True)
  humanomni/model/encoder.py:240-241     'siglip' in vision_tower -> SiglipVisionTower
  humanomni/model/__init__.py:85         vision_tower.load_model()                <- the sink
  humanomni/model/encoder.py:112,114     SiglipImageProcessor/SiglipVisionModel.from_pretrained(<field>)

`load_pretrained_model` is called with device="cpu" because `model_init` hardcodes
device="cuda"; the vulnerable read at humanomni/model/__init__.py:85 is reached
identically (it happens before the tower is moved to a device).
"""

import json
import os
import sys
import traceback
from pathlib import Path

POC = Path(__file__).resolve().parent
SRC = POC / "R1-Omni-17cafca"
ARTIFACTS = {"positive": Path("/model"), "negative": Path("/model-negative")}
EXTERNAL = Path("/external/siglip-positive-canary")

ARM = sys.argv[1] if len(sys.argv) > 1 else "positive"
if ARM not in ARTIFACTS:
    sys.exit(f"usage: {sys.argv[0]} [positive|negative]")
ART = ARTIFACTS[ARM]
IN_PACKAGE = ART / "siglip-vision"

# Mirror the environment the repository's own entry point sets (inference.py:8).
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_HUB_OFFLINE"] = "1"

LINE = "-" * 74

# ---------------------------------------------------------------------------
# record every path the process touches below the artifact and the fixture roots
# ---------------------------------------------------------------------------
WATCH = ("/model", "/external", "/mnt/data/jiaxing.zjx")
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


def show_watched(label, prefix):
    found = watched(prefix)
    files = sorted({p for p in found if os.path.isfile(p)})
    names = [os.path.relpath(p, str(prefix)) for p in files]
    print(f"  {label}")
    print(f"      paths touched : {len(found)}")
    print(f"      files opened  : {len(names)}  {names if names else '[]'}")


def main():
    print("=" * 74)
    print(f"R1-Omni / HumanOmni directed model load -- {ARM.upper()} arm")
    print("=" * 74)
    print(f"pinned source   : {SRC}")
    print(f"victim loads    : {ART}   (python inference.py --model_path {ART})")

    pkg = json.loads((ART / "config.json").read_text(encoding="utf-8"))
    field = pkg["mm_vision_tower"]
    outside = not field.startswith(str(ART) + "/")
    print(f"package field   : mm_vision_tower = {field!r}")
    print(f"                  -> outside the artifact root {ART}: {outside}")
    print()

    sys.path.insert(0, str(SRC))
    import torch
    from humanomni.model import load_pretrained_model

    print(LINE)
    print("loading through the real upstream loader (no patching, no stubs)")
    print(LINE)
    try:
        tokenizer, model, processor, context_len, audio_processor = load_pretrained_model(
            str(ART), None, "HumanOmni_7B", device_map="cpu", device="cpu")
    except Exception:
        print("load_pretrained_model raised:")
        traceback.print_exc()
        return 2

    tower = model.get_vision_tower()
    cfg = tower.vision_tower.config
    resolved = str(getattr(cfg, "_name_or_path", "?"))
    bias = tower.vision_tower.vision_model.embeddings.patch_embedding.bias
    bias_mean = float(bias.detach().float().mean())

    print("load_pretrained_model: OK")
    print(f"  tokenizer            : {type(tokenizer).__name__}")
    print(f"  model.config.model_type: {model.config.model_type}")
    print(f"  context_len          : {context_len}")
    print(f"  audio_processor      : {audio_processor}")
    print()
    print(LINE)
    print("what the loader actually read for the second model")
    print(LINE)
    print(f"  wrapper class chosen : {type(tower).__name__}   (encoder.py:240-241, substring 'siglip')")
    print(f"  raw field value      : {tower.vision_tower_name}")
    print(f"  resolved directory   : {resolved}")
    print(f"  siglip config marker : {getattr(cfg, 'poc_arm_marker', None)!r}")
    print(f"  processor marker     : {getattr(tower.image_processor, 'poc_arm_marker', None)!r}")
    print(f"  processor is the one the model uses: {processor is tower.image_processor}")
    print(f"  weight marker        : patch_embedding.bias mean = {bias_mean:+.6f}")
    print(f"  hidden_size / patches: {tower.hidden_size} / {tower.num_patches_per_side}x{tower.num_patches_per_side}")
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
    show_watched(f"OUTSIDE the artifact  {EXTERNAL}", EXTERNAL)
    show_watched(f"INSIDE the artifact   {IN_PACKAGE}", IN_PACKAGE)
    show_watched(f"the artifact itself   {ART}", ART)
    print()

    # -----------------------------------------------------------------------
    # the loaded (attacker-chosen) weights are really used for vision encoding
    # -----------------------------------------------------------------------
    print(LINE)
    print("vision forward pass through the same tower the loader built")
    print(LINE)
    img = torch.rand(1, 3, 32, 32)
    try:
        with torch.no_grad():
            feats = tower(img)
        how = f"dtype {tower.dtype}"
    except Exception as exc:                                   # noqa: BLE001
        print(f"  forward in {tower.dtype} failed ({type(exc).__name__}: {exc}); retrying in float32")
        tower.float()
        with torch.no_grad():
            feats = tower(img)
        how = f"float32 fallback (original dtype {tower.dtype} unsupported on this CPU build)"
    print(f"  input  : {tuple(img.shape)}")
    print(f"  output : {tuple(feats.shape)}   ({how})")
    print(f"  output dtype/mean: {feats.dtype} / {float(feats.float().mean()):+.6f}")
    print()

    print()
    print(LINE)
    print(f"EVIDENCE SUMMARY ({ARM} arm)")
    print(LINE)
    marker = getattr(cfg, "poc_arm_marker", None)
    outside_files = sorted({p for p in watched(EXTERNAL) if os.path.isfile(p)})
    inside_files = sorted({p for p in watched(IN_PACKAGE) if os.path.isfile(p)})
    print(f"  victim loads the package       : {ART}")
    print("  loader driven                  : humanomni.model.load_pretrained_model")
    print("                                   (pinned upstream copy, unmodified)")
    print(f"  package field mm_vision_tower  : {field}")
    print(f"  points outside the artifact    : {outside}")
    print(f"  wrapper chosen by encoder.py   : {type(tower).__name__}  ('siglip' substring)")
    print(f"  directory actually loaded      : {resolved}")
    print(f"  config marker read             : {getattr(cfg, 'poc_arm_marker', None)}")
    print(f"  weight marker read (bias mean) : {bias_mean:+.6f}")
    print(f"  arm-exclusive tensors in file  : {exclusive}")
    print(f"  files opened OUTSIDE artifact  : {len(outside_files)}"
          f" {[os.path.relpath(p, str(EXTERNAL)) for p in outside_files]}")
    print(f"  files opened in-package copy   : {len(inside_files)}")
    print(f"  vision forward pass            : {tuple(img.shape)} -> {tuple(feats.shape)}")
    print(LINE)
    if ARM == "positive":
        if outside and marker == "EXTERNAL-POSITIVE-ARM":
            print("  RESULT: EXTERNAL SECOND MODEL LOADED")
            print("          no path constraint, no warning, load returns OK")
        else:
            print(f"  UNEXPECTED: outside={outside} marker={marker!r}")
            return 3
    else:
        if not outside and marker == "IN-PACKAGE-CONTROL-ARM":
            print("  RESULT: control arm read ONLY the in-package copy")
            print("          the single field decides which directory is loaded")
        else:
            print(f"  UNEXPECTED: outside={outside} marker={marker!r}")
            return 3
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
