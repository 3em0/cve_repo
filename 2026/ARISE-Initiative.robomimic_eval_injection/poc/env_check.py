#!/usr/bin/env python3
"""
env_check.py -- show the exact component versions inside the reproduction container.

Part of the reproduction kit for:
  ARISE-Initiative/robomimic @ d309eaecc18acf4152a830a895a6984b8ac71b05
  pooled-class eval() code execution (robomimic/models/obs_core.py:121-122)
"""
import sys

import numpy
import torch
import torchvision
import h5py
import robomimic


def main():
    print("python      :", sys.version.split()[0])
    print("torch       :", torch.__version__, "(cuda available:", torch.cuda.is_available(), ")")
    print("torchvision :", torchvision.__version__)
    print("numpy       :", numpy.__version__)
    print("h5py        :", h5py.__version__)
    print("robomimic   :", robomimic.__version__)
    print("robomimic at:", robomimic.__file__)


if __name__ == "__main__":
    main()
