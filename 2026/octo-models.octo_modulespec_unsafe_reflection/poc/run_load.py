#!/usr/bin/env python3
"""Load one checkpoint through the documented public API and report what happened.

    python run_load.py checkpoints/octo-checkpoint-positive
    python run_load.py checkpoints/octo-checkpoint-negative

The two runs must end at the same exception; the only observable difference is
whether the ModuleSpec in config.json was instantiated with delay=False (which
opens the sink file immediately) or delay=True (which does not).
"""
import os
import sys
import traceback
from pathlib import Path

from octo.model.octo_model import OctoModel

SINK = "/out/octo_modulespec_sink_marker"


def main():
    if len(sys.argv) != 2:
        print("usage: python run_load.py <checkpoint-dir>")
        return 2

    path = Path(sys.argv[1]).resolve()
    print(f'OctoModel.load_pretrained("{path}")')
    print("-" * 74)

    try:
        OctoModel.load_pretrained(str(path))
    except Exception as exc:  # noqa: BLE001 - the failure point is the evidence
        tb = traceback.format_exc().rstrip().splitlines()
        print("load_pretrained raised:", type(exc).__name__)
        print()
        for line in tb[-12:]:
            print(line)
    else:
        print("load_pretrained returned a model")

    print()
    print(f"checkpoint         : {path}")
    print(f"sink file exists   : {os.path.exists(SINK)}  ({SINK})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
