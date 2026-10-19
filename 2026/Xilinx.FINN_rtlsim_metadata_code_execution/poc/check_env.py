#!/usr/bin/env python3
"""Print the reproduction environment and the provenance of the vulnerable file.

Usage:  python check_env.py
"""

import hashlib
import os
import sys

VULN_FILE = "src/finn/core/rtlsim_exec.py"
VULN_LINE = 'if_dict = eval(model.get_metadata_prop("vivado_stitch_ifnames"))'


def versions():
    print("python      :", sys.version.split()[0], "(%s)" % sys.executable)
    for mod in ("onnx", "qonnx", "numpy", "torch"):
        try:
            m = __import__(mod)
            print("%-12s: %s" % (mod, getattr(m, "__version__", "(no __version__)")))
        except Exception as exc:  # pragma: no cover
            print("%-12s: MISSING (%s)" % (mod, type(exc).__name__))
    root = os.environ.get("FINN_ROOT", "(FINN_ROOT unset)")
    print("FINN_ROOT   :", root)
    print("FINN_BUILD_DIR:", os.environ.get("FINN_BUILD_DIR", "(unset)"))

    if not os.path.isdir(root):
        print("\nFINN source tree not found - set FINN_ROOT to the pinned checkout")
        return

    path = os.path.join(root, VULN_FILE)
    if not os.path.isfile(path):
        print("\n%s not found under FINN_ROOT" % VULN_FILE)
        return
    with open(path, "rb") as f:
        data = f.read()
    print("\n%s" % path)
    print("  sha256:", hashlib.sha256(data).hexdigest())
    print("  lines :", data.decode("utf-8", "replace").count("\n") + 1)
    for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if VULN_LINE in line:
            print("  sink  : line %d: %s" % (i, line.strip()))
    for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if "ifnames = eval(ifnames)" in line:
            print("  sink  : line %d: %s" % (i, line.strip()))


if __name__ == "__main__":
    versions()
