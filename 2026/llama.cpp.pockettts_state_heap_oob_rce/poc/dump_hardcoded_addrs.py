#!/usr/bin/env python3
"""Dump the hard-coded addresses carried inside the pocket-tts artifact.

The artifact is a GGUF whose upsample/quant weights encode arbitrary 32-bit words
as exact F32 values, so reading the raw bit patterns of those weights reveals the
heap and libc addresses the exploit was calibrated against.  Comparing them with
the addresses measured in the current environment tells us whether a failed run is
caused by an address mismatch or by something else.

Run (uses the ASan lab image, which already has python3 + gguf + numpy):

  docker run --rm -v "<package>:/pkg:ro" -v "<poc>:/poc:ro" \
      --entrypoint /opt/venv/bin/python3 llamacpp-mmproj-asan:3d82ef62 \
      /poc/dump_hardcoded_addrs.py
"""
import collections
import sys

import numpy as np
import gguf

PATH = sys.argv[1] if len(sys.argv) > 1 else \
    '/pkg/artifact/mmproj_evil_pockettts_worldg31.gguf'

reader = gguf.GGUFReader(PATH)
print(f"reading {PATH}")

for tensor in reader.tensors:
    name = tensor.name
    if not any(k in name for k in ("upsample", "quant_out", "emb_mean", "emb_std")):
        continue
    arr = np.asarray(tensor.data)
    print(f"\ntensor {name}  shape={arr.shape}  dtype={arr.dtype}")
    if arr.dtype != np.float32:
        continue
    bits = np.ascontiguousarray(arr).view(np.uint32).ravel()
    counts = collections.Counter(bits.tolist())

    heap = sorted(v for v in counts if 0x55550000 <= v <= 0x5555FFFF)
    libc = sorted(v for v in counts if 0x7FFFF000 <= v <= 0x7FFFFFFF)
    other = sorted(v for v in counts if v > 0xFFFF and v not in heap and v not in libc)

    print(f"  distinct 32-bit values: {len(counts)}")
    print(f"  heap-shaped  (0x5555xxxx): {len(heap)}")
    for v in heap:
        print(f"    0x{v:08x}   x{counts[v]}")
    print(f"  libc-shaped  (0x7fffxxxx): {len(libc)}")
    for v in libc:
        print(f"    0x{v:08x}   x{counts[v]}")
    if len(other) <= 40:
        print(f"  other > 0xffff: {len(other)}")
        for v in other:
            print(f"    0x{v:08x}   x{counts[v]}")
