#!/usr/bin/env python3
"""Outer-boundary control: read the malicious artifact with the safe parser only.

The safetensors container is parsed by the safetensors library itself
(``safe_open`` for the metadata, ``load_file`` for the tensors).  Those calls
return a well-formed uint8 tensor and execute nothing: the deserialization
terminal is the *second* stage, driven by ``metadata["non_tensor_keys"]`` inside
``colossalai.utils.safetensors._unflatten_optim_state_dict()``.

This script performs only the outer stage and reports the metadata and the
tensor inventory, so the two boundaries can be told apart in the transcript.
"""

import json
import os
import sys

from safetensors import safe_open
from safetensors.torch import load_file


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python outer_parser_control.py <optimizer-checkpoint.safetensors>")
        return 2

    checkpoint = sys.argv[1]
    marker = "PWNED.txt"
    if os.path.exists(marker):
        os.remove(marker)
    print(f"marker {marker!r} removed before the run: {not os.path.exists(marker)}")

    with safe_open(checkpoint, framework="pt") as handle:
        metadata = handle.metadata()
        keys = list(handle.keys())
    tensors = load_file(checkpoint)

    print("outer stage: safetensors.safe_open() + safetensors.torch.load_file()")
    print(f"  metadata               : {json.dumps(metadata)}")
    print(f"  tensor keys            : {sorted(keys)}")
    for key in sorted(tensors):
        value = tensors[key]
        print(f"  {key} -> torch.Tensor dtype={value.dtype} shape={tuple(value.shape)}")

    named = json.loads(metadata.get("non_tensor_keys", "[]"))
    print(f"  keys the metadata sends to the object loader: {named}")
    print(f"marker {marker!r} exists after the run: {os.path.exists(marker)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
