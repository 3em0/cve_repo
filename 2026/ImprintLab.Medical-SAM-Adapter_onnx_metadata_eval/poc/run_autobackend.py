#!/usr/bin/env python3
"""Library-constructor-level runner.

Loads a .onnx through the installed ultralytics copy's own AutoBackend -- the
ordinary library action for a model file -- and then reports, honestly, what
it observes on disk and in the parsed metadata.  This script never fabricates
output: every line is printed from a real check performed after the
constructor returns (or at the moment it raises).

Usage:  python run_autobackend.py <path/to/model.onnx>

Canary convention (must match make_poc.py): the payload writes
./pwned_by_w11_yolov13_onnx_meta into the CURRENT WORKING DIRECTORY.
"""
import pathlib
import sys

import ultralytics

CANARY = pathlib.Path("pwned_by_w11_yolov13_onnx_meta")

weights = sys.argv[1] if len(sys.argv) > 1 else "artifacts/evil.onnx"
print("ultralytics", ultralytics.__version__,
      "| autobackend.py:", pathlib.Path(ultralytics.__file__).parent / "nn" / "autobackend.py")
print("[step] calling AutoBackend(weights=%r)  <- the library's ordinary action" % weights)
try:
    from ultralytics.nn.autobackend import AutoBackend
    model = AutoBackend(weights=weights)
except Exception as e:
    print("[result] AutoBackend raised:", type(e).__name__, str(e)[:200])
    raise
print("[result] constructor returned normally")
print("[verify] canary file present :", CANARY.exists())
if CANARY.exists():
    print("[verify] canary content      :", CANARY.read_text())
names = getattr(model, "names", None)
print("[verify] names from metadata :", names)
