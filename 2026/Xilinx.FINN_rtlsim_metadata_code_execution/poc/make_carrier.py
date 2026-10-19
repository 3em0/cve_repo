#!/usr/bin/env python3
"""PoC stage 1 - produce the FINN dataflow "carrier" model.

This is the attacker-side preparation step.  It takes the QONNX example network
that ships with FINN (``src/finn/qnn-data/build_dataflow/model.onnx``) and runs the
documented FINN build phases up to layer specialisation, i.e. exactly what a FINN
user does before a hardware build.  The resulting checkpoint is a genuine FINN
dataflow model (FINN HLS/RTL custom ops) - the kind of ONNX file that is passed
around as a model package for ``python -m finn.builder.build_dataflow``.

Output: ``carrier/dataflow_model.onnx``

Run it with a FINN environment, e.g.

    export FINN_ROOT=~/work/finn-src
    export FINN_BUILD_DIR=~/work/finn_build_dir
    ~/work/fv311/bin/python make_carrier.py
"""

import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    finn_root = os.environ.get("FINN_ROOT")
    if not finn_root:
        sys.exit("FINN_ROOT must be set (point it at the pinned FINN checkout)")

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--src-pkg",
        default=os.path.join(finn_root, "src", "finn", "qnn-data", "build_dataflow"),
        help="FINN's shipped example model package (QONNX input model)",
    )
    ap.add_argument("--out", default=os.path.join(HERE, "carrier"))
    ap.add_argument(
        "--work", default=os.path.join(os.path.expanduser("~"), "work", "carrier_build")
    )
    args = ap.parse_args()

    if not os.path.isfile(os.path.join(args.src_pkg, "model.onnx")):
        sys.exit("example model not found under " + args.src_pkg)

    # FINN needs a scratch build dir and a writable cwd holding the input model
    os.environ.setdefault(
        "FINN_BUILD_DIR", os.path.join(os.path.expanduser("~"), "work", "finn_build_dir")
    )
    os.makedirs(os.environ["FINN_BUILD_DIR"], exist_ok=True)
    shutil.rmtree(args.work, ignore_errors=True)
    os.makedirs(args.work)
    for fn in ("model.onnx", "folding_config.json", "specialize_layers_config.json"):
        shutil.copy2(os.path.join(args.src_pkg, fn), os.path.join(args.work, fn))
    os.chdir(args.work)

    import finn.builder.build_dataflow as build
    from finn.builder.build_dataflow_config import DataflowBuildConfig

    cfg = DataflowBuildConfig(
        output_dir=os.path.join(args.work, "output_carrier"),
        synth_clk_period_ns=10.0,
        generate_outputs=[],
        target_fps=100000,
        mvau_wwidth_max=10000,
        board="ZCU104",
        standalone_thresholds=False,
        folding_config_file="folding_config.json",
        specialize_layers_config_file="specialize_layers_config.json",
        save_intermediate_models=True,
        # stop right after layer specialisation: a pure-Python, toolchain-free checkpoint
        steps=[
            "phase_prepare_model",
            "phase_optimize_model",
            "step_convert_to_hw",
            "step_specialize_layers",
        ],
    )
    ret = build.build_dataflow_cfg("model.onnx", cfg)
    if ret != 0:
        sys.exit("carrier build failed")

    src = os.path.join(
        args.work, "output_carrier", "intermediate_models", "step_specialize_layers.onnx"
    )
    if not os.path.isfile(src):
        sys.exit("expected checkpoint not produced: " + src)

    os.makedirs(args.out, exist_ok=True)
    dst = os.path.join(args.out, "dataflow_model.onnx")
    shutil.copy2(src, dst)

    # report what the carrier looks like
    from collections import Counter

    from qonnx.core.modelwrapper import ModelWrapper

    m = ModelWrapper(dst)
    ops = Counter(n.op_type for n in m.graph.node)
    print("\n=== carrier model written to %s ===" % dst)
    print("op types     :", dict(ops))
    print("graph inputs :", [i.name for i in m.graph.input])
    print("graph outputs:", [o.name for o in m.graph.output])
    print("in shape     :", m.get_tensor_shape(m.get_first_global_in()))
    print("out shape    :", m.get_tensor_shape(m.get_first_global_out()))
    print("metadata keys:", [p.key for p in m.model.graph.metadata_props])


if __name__ == "__main__":
    main()
