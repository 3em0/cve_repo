#!/usr/bin/env python3
"""List every distinct 32-bit word carried by the artifact's upsample weights.

The planted chunk-metadata values (fake top size, fence sizes, footers) are small
integers beside the addresses, so this prints the whole word table with counts and
the buffer-word index each carrier sits at.
"""
import collections
import sys

import numpy as np
import gguf

PATH = sys.argv[1]
TENSOR = "a.gen.wav.upsample.weight"

reader = gguf.GGUFReader(PATH)
tensor = next(t for t in reader.tensors if t.name == TENSOR)
arr = np.asarray(tensor.data).view(np.uint32).ravel()
counts = collections.Counter(arr.tolist())

print(f"{PATH}")
print(f"{TENSOR}: {arr.size} words, {len(counts)} distinct")
for value in sorted(counts):
    print(f"  0x{value:08x}  x{counts[value]}")
