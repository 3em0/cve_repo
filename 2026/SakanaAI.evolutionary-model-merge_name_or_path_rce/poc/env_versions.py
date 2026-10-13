#!/usr/bin/env python
"""Report the versions actually installed in the reproduction container."""

import platform
import sys

import torch
import transformers

print("python      :", sys.version.split()[0], f"({platform.system()} {platform.machine()})")
print("torch       :", torch.__version__, "| cuda available:", torch.cuda.is_available())
print("transformers:", transformers.__version__)
