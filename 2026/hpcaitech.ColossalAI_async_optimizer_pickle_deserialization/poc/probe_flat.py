#!/usr/bin/env python3
"""Call the vulnerable loader directly and show what each flat entry became.

``colossalai.utils.safetensors.load_flat()`` is the function every async
optimizer-load path in the product goes through (GeneralCheckpointIO:178,
LowLevelZeroPlugin:156, TorchFSDPPlugin:59, HybridParallelCheckpointIO:725/983,
checkpoint_io/utils.py:994).  Printing the Python type of every restored entry
shows which tensors the file's own metadata sent to the object loader.
"""

import sys

import torch

from colossalai.utils.safetensors import load_flat


def describe(value) -> str:
    if isinstance(value, torch.Tensor):
        return f"torch.Tensor dtype={value.dtype} shape={tuple(value.shape)}"
    return f"{type(value).__module__}.{type(value).__name__}: {value!r}"[:120]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python probe_flat.py <optimizer-checkpoint.safetensors>")
        return 2

    checkpoint = sys.argv[1]
    print(f"load_flat({checkpoint!r})")
    state_dict = load_flat(checkpoint)
    print(f"restored keys: {sorted(state_dict.keys())}")
    for key in sorted(state_dict.keys()):
        value = state_dict[key]
        if isinstance(value, dict):
            for sub_key in sorted(value.keys()):
                print(f"  {key}[{sub_key!r}] -> {describe(value[sub_key])}")
        else:
            print(f"  {key!r} -> {describe(value)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
