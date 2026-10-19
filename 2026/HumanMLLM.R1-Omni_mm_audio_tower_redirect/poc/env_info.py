#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Print the reproduction environment: interpreter + the libraries the loader uses.

Short on purpose: the screenshot scenario types `python env_info.py` so the
environment evidence does not depend on a long quoted one-liner.
"""

import sys
import platform


def show(label, getter):
    try:
        print(f"{label:<14} {getter()}")
    except Exception as exc:                                   # noqa: BLE001
        print(f"{label:<14} [unavailable: {type(exc).__name__}: {exc}]")


print(f"{'python':<14} {sys.version.split()[0]}  ({sys.executable})")
print(f"{'platform':<14} {platform.platform()}")
try:
    import torch
    print(f"{'torch':<14} {torch.__version__}  (cuda available: {torch.cuda.is_available()})")
except Exception as exc:                                       # noqa: BLE001
    print(f"{'torch':<14} [unavailable: {exc}]")
show("transformers", lambda: __import__("transformers").__version__)
show("safetensors", lambda: __import__("safetensors").__version__)
show("tokenizers", lambda: __import__("tokenizers").__version__)
show("timm", lambda: __import__("timm").__version__)
show("einops", lambda: __import__("einops").__version__)
show("numpy", lambda: __import__("numpy").__version__)
show("accelerate", lambda: __import__("accelerate").__version__)
show("huggingface_hub", lambda: __import__("huggingface_hub").__version__)
