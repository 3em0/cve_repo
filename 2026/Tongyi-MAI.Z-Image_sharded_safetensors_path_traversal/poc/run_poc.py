#!/usr/bin/env python
"""run_poc.py -- drive the product's own functions against one model package.

The three entry points below are the product's code, imported from the pinned source
that is unpacked into /opt/Z-Image; nothing about the loader is re-implemented here.

    gate  <pkg>   ensure_model_weights(<pkg>, verify=False)          # inference.py:15
    shard <pkg>   load_sharded_safetensors(<pkg>/transformer, ...)   # src/utils/loader.py:50-71
    load  <pkg>   load_from_local_dir(<pkg>, device="cpu", ...)      # inference.py:51
"""

import json
import os
import sys
from pathlib import Path

SRC = Path(os.environ.get("ZIMAGE_SRC", "/opt/Z-Image/src"))
sys.path.insert(0, str(SRC))

import torch  # noqa: E402
from safetensors.torch import load_file  # noqa: E402

from utils import ensure_model_weights  # noqa: E402  (product helper, inference.py:10)
from utils.loader import load_from_local_dir, load_sharded_safetensors  # noqa: E402


def banner(title):
    print("")
    print("-" * 78)
    print(title)
    print("-" * 78)


def inside(path, base):
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def label_for(path, base):
    """Shard name as it appears inside the package, full path when it escapes."""
    return path.name if inside(path, base) else str(path)


def display(path):
    """Shortest honest rendering: relative to the current directory when possible."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def print_env():
    import loguru
    import safetensors
    import transformers

    print(f"[driver] python {sys.version.split()[0]} | torch {torch.__version__} | "
          f"transformers {transformers.__version__}")
    print(f"[driver] safetensors {safetensors.__version__} | loguru {loguru.__version__}")


def mode_gate(pkg):
    banner("product call: ensure_model_weights(<package>, verify=False)   # inference.py:15")
    print(f"[driver] package: {pkg}")
    resolved = ensure_model_weights(str(pkg), verify=False)
    print(f"[driver] gate returned: {resolved}")
    print("[driver] note: with verify=False -- the argument inference.py:15 passes -- the")
    print("[driver]       manifest check is existence-only, so the package passes even")
    print("[driver]       though one index value points outside the model directory")
    return 0


def mode_shard(pkg):
    transformer_dir = pkg / "transformer"
    index_path = transformer_dir / "diffusion_pytorch_model.safetensors.index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    weight_map = index["weight_map"]
    value = weight_map["x_pad_token"]
    resolved = transformer_dir / value

    banner("product call: load_sharded_safetensors(<pkg>/transformer, device='cpu')   # loader.py:50-71")
    print(f"[driver] model directory: {transformer_dir}")
    print(f"[driver] weight_map['x_pad_token']: {value}")
    print(f"[driver] Path(model_dir) / value: {resolved}")
    print(f"[driver] escapes the model directory: {not inside(resolved, transformer_dir)}")
    print("")
    print("[driver] files named by the index:")
    counts = {}
    for shard in weight_map.values():
        counts[shard] = counts.get(shard, 0) + 1
    for name in sorted(counts, key=lambda n: (not inside(transformer_dir / n, transformer_dir),
                                              label_for(transformer_dir / n, transformer_dir))):
        target = transformer_dir / name
        where = "inside " if inside(target, transformer_dir) else "OUTSIDE"
        print(f"[driver]   {label_for(target, transformer_dir):<52} {where} package  "
              f"({counts[name]:>2} keys)")

    try:
        state = load_sharded_safetensors(transformer_dir, device="cpu", dtype=None)
    except Exception as exc:  # noqa: BLE001 - the product loader's own error is the evidence
        print("")
        print(f"[driver] product loader raised {type(exc).__name__}: {exc}")
        return 1

    tensor = state["x_pad_token"]
    reference = load_file(str(resolved), device="cpu")["x_pad_token"]
    print("")
    print(f"[driver] tensors returned: {len(state)}")
    print(f"[driver] x_pad_token: shape {tuple(tensor.shape)}, dtype {tensor.dtype}")
    print(f"[driver] loaded from: {display(resolved)}")
    print(f"[driver] equals the tensor stored there: {torch.equal(tensor, reference.to(tensor.dtype))}")
    print("[driver] this tensor enters the model load (load_state_dict)")
    return 0


def mode_load(pkg):
    banner('product call: load_from_local_dir(<package>, device="cpu", dtype=torch.bfloat16)   # inference.py:51')
    print(f"[driver] package: {pkg}")
    try:
        components = load_from_local_dir(str(pkg), device="cpu", dtype=torch.bfloat16)
    except Exception as exc:  # noqa: BLE001 - the product's own error is the evidence
        print(f"[driver] product entry raised {type(exc).__name__}:")
        for line in str(exc).rstrip().splitlines():
            print(f"    {line}")
        return 1
    print(f"[driver] load_from_local_dir returned {len(components)} components")
    return 0


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if len(sys.argv) != 3 or sys.argv[1] not in ("gate", "shard", "load"):
        print(__doc__)
        return 2
    mode, pkg = sys.argv[1], Path(sys.argv[2]).resolve()
    if not (pkg / "transformer").is_dir():
        print(f"[driver] not a model package: {pkg}")
        return 2

    banner("Z-Image shard-index PoC")
    print(f"[driver] mode   : {mode}")
    print(f"[driver] package: {pkg}")
    print_env()

    return {"gate": mode_gate, "shard": mode_shard, "load": mode_load}[mode](pkg)


if __name__ == "__main__":
    sys.exit(main())
