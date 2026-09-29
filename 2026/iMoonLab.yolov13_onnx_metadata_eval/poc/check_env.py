#!/usr/bin/env python3
"""Environment proof for the 2026-09-29 screenshot run.

Prints the interpreter and the exact ultralytics copy in use, then hashes the
installed nn/autobackend.py and compares it byte-for-byte against the copies
vendored by the four repositories at their audited HEAD commits (hashes
re-fetched live from github.com on 2026-09-29 and matching the corpus records
of 2026-09-18 / 2026-09-24).
"""
import hashlib
import pathlib
import sys

import ultralytics

VENDORED = {
    "iMoonLab/yolov13 @ 73289949533efac82bb5f72ec19b746618656bd2 (vendors 8.3.63)":
        "38d2f06254fcb6eebf5348215df70d986e9e1fd5161fe1c3c270501f699b616b",
    "THU-MIG/yoloe @ 40cd606cabdbe2b566d6f14a6b162c89206e9a1b (vendors 8.3.39)":
        "02b91ee41691426af8c9077ec6be99f0fee46d304d2c8f8ed1fb033c52ce5ccc",
    "CASIA-LMC-Lab/FastSAM @ b4ed20c2fed75eadc5aa7d8b09fedd137b873b52 (vendors 8.0.120)":
        "55a5363f49f0a63d18d07c01264fabd7e3fab7cfbdeb9125e5bf43d642b0c4d8",
    "ImprintLab/Medical-SAM-Adapter @ 5888e722876511f177e8e762498a7986753b7f7d (vendors 8.0.120)":
        "55a5363f49f0a63d18d07c01264fabd7e3fab7cfbdeb9125e5bf43d642b0c4d8",
}

print("python          :", sys.version.split()[0])
print("ultralytics     :", ultralytics.__version__)
print("package location:", pathlib.Path(ultralytics.__file__).parent)
ab = pathlib.Path(ultralytics.__file__).parent / "nn" / "autobackend.py"
h = hashlib.sha256(ab.read_bytes()).hexdigest()
print("autobackend.py sha256:")
print("  ", h)
print("byte-identity vs the four vendored copies:")
for name, vh in VENDORED.items():
    print(f"   {'MATCH   ' if h == vh else 'DIFFERS '} {name}")
