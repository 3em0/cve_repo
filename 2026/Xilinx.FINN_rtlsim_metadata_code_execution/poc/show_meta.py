#!/usr/bin/env python3
"""Dump the ONNX metadata of a model package, so the attack field can be inspected.

Usage:  python show_meta.py artifacts/evil
        python show_meta.py artifacts/benign
"""

import os
import sys

import onnx


def dump(title, props):
    print("%s (%d entries)" % (title, len(props)))
    for p in props:
        value = p.value
        if len(value) > 200:
            value = value[:200] + " ..."
        print("    %-22s = %s" % (p.key, value))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    pkg = sys.argv[1]
    path = os.path.join(pkg, "model.onnx")
    model = onnx.load(path)
    print("package :", pkg)
    print("file    : %s (%d bytes)" % (path, os.path.getsize(path)))
    ops = [n.op_type for n in model.graph.node]
    print("op types:", ops)
    print()
    dump("graph.metadata_props", model.graph.metadata_props)
    print()
    dump("model.metadata_props", model.metadata_props)
    print()
    print("NOTE  FINN reads vivado_stitch_ifnames through qonnx ModelWrapper,")
    print("      which resolves graph.metadata_props in the pinned environment.")


if __name__ == "__main__":
    main()
