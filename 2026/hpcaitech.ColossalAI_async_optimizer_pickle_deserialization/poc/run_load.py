#!/usr/bin/env python3
"""Drive ColossalAI's own optimizer-checkpoint loader on a delivered artifact.

This is the interface a user reaches through the public Booster API:

    booster.load_optimizer(optimizer, checkpoint)
      -> plugin.load_optimizer(...)                     (e.g. LowLevelZeroPlugin:149)
      -> self.load_unsharded_optimizer(optimizer, checkpoint)
      -> colossalai/checkpoint_io/general_checkpoint_io.py:174-183
             if checkpoint.endswith(".safetensors"):
                 checkpoint = load_flat(checkpoint)     <- the vulnerable loader
             optimizer.load_state_dict(checkpoint)

The plugin layer needs a distributed launcher (deepspeed/ZeRO), so this driver
calls the same ``GeneralCheckpointIO.load_unsharded_optimizer()`` method the
plugin delegates to, on a real ``torch.optim.Adam`` optimizer.
"""

import sys

import torch

from colossalai.checkpoint_io import GeneralCheckpointIO


def build_optimizer() -> torch.optim.Optimizer:
    torch.manual_seed(0)
    model = torch.nn.Linear(4, 2)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    model(torch.randn(3, 4)).sum().backward()
    optimizer.step()
    return optimizer


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python run_load.py <optimizer-checkpoint.safetensors>")
        return 2

    checkpoint = sys.argv[1]
    print("entry    : colossalai.checkpoint_io.GeneralCheckpointIO.load_unsharded_optimizer")
    print(f"artifact : {checkpoint}")
    print(f"exists   : {__import__('os').path.exists(checkpoint)}")

    optimizer = build_optimizer()
    GeneralCheckpointIO().load_unsharded_optimizer(optimizer, checkpoint)

    state = optimizer.state_dict()["state"]
    print("restored : optimizer.load_state_dict() returned without raising")
    print(f"restored state[0] keys: {sorted(state[0].keys())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
