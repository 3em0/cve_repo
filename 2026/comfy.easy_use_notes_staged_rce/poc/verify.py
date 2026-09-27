#!/usr/bin/env python3
"""verify.py -- read back the on-disk effects of the live reproduction.

Prints, from the live stack root configured in live_config.json:
  * sha256 of custom_nodes/ComfyUI-Easy-Use/__init__.py (the overwritten initializer)
  * the pristine-pinned hash for comparison
  * STAGE2_CANARY.txt (written by the stage-2 sentinel when the product imported it)
  * input/mbe2e_stage2.py (staged by the payload through POST /upload/image)
  * how many startup banners the server log carries (one per product lifetime)
"""
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
_cfg = {}
_cfg_path = HERE / "live_config.json"
if _cfg_path.exists():
    _cfg = json.loads(_cfg_path.read_text(encoding="utf-8"))
LIVE = pathlib.Path(_cfg.get("root", str(HERE / "live" / "ComfyUI")))
EXT_INIT = LIVE / "custom_nodes" / "ComfyUI-Easy-Use" / "__init__.py"
CANARY = LIVE / "custom_nodes" / "ComfyUI-Easy-Use" / "STAGE2_CANARY.txt"
STAGE2_UPLOADED = LIVE / "input" / "mbe2e_stage2.py"
SERVER_LOG = LIVE / "comfyui_detail.log"
PRISTINE = HERE / "ComfyUI-Easy-Use-450b1ce4" / "__init__.py"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    print("live root:", LIVE)
    print("pristine __init__.py sha256 :", sha(PRISTINE))
    print("current __init__.py sha256  :", sha(EXT_INIT))
    print("initializer overwritten     :", sha(PRISTINE) != sha(EXT_INIT))
    if CANARY.exists():
        print("STAGE2_CANARY.txt           :", CANARY.read_text(encoding="utf-8").strip())
    else:
        print("STAGE2_CANARY.txt           : absent")
    if STAGE2_UPLOADED.exists():
        print("input/mbe2e_stage2.py       : present,", STAGE2_UPLOADED.stat().st_size, "bytes")
    else:
        print("input/mbe2e_stage2.py       : absent")
    if SERVER_LOG.exists():
        n = SERVER_LOG.read_text("utf-8", "replace").count("To see the GUI go to")
        print("server startup banners      :", n)
    else:
        print("server startup banners      : no log file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
