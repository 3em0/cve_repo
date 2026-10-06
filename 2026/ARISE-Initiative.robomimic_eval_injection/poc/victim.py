#!/usr/bin/env python3
"""
victim.py -- drive the real public robomimic entry point on a checkpoint file.

This performs exactly what a downstream user does to run a published policy:

    robomimic.utils.file_utils.policy_from_checkpoint(ckpt_path=...)

Chain inside robomimic:

    policy_from_checkpoint
      -> maybe_dict_from_checkpoint / load_dict_from_checkpoint
           torch.load(ckpt_path, ..., weights_only=False)
      -> config_from_checkpoint
           json.loads(ckpt_dict["config"])          # the embedded config JSON string
           config_factory(algo_name, dic=config_dict)
      -> ObsUtils.initialize_obs_utils_with_config(config)
      -> algo_factory(...)                          # rebuilds networks
           -> ObsEncoder -> VisualCore.__init__
                -> eval(pool_class)                 # <-- defect, obs_core.py:121-122

Usage:  python victim.py ckpt/benign.pth
        python victim.py ckpt/malicious.pth
"""
import sys

import torch

import robomimic.utils.file_utils as FileUtils


def main():
    if len(sys.argv) != 2:
        print("usage: python victim.py <checkpoint.pth>")
        return 2

    ckpt_path = sys.argv[1]
    print("[victim] FileUtils.policy_from_checkpoint(ckpt_path={!r})".format(ckpt_path))

    policy, ckpt_dict = FileUtils.policy_from_checkpoint(
        ckpt_path=ckpt_path, device=torch.device("cpu"))

    print("[victim] returned : {}".format(type(policy).__name__))
    print("[victim] algo_name: {}".format(ckpt_dict["algo_name"]))

    # Report which pooling class the rebuilt network ended up with.
    try:
        cores = [(name, mod) for name, mod in policy.policy.nets.named_modules()
                 if type(mod).__name__ == "VisualCore"]
        for name, core in cores:
            print("[victim] {} .pool instance: {}".format(
                name or "<root>", type(core.pool).__name__))
    except Exception as exc:  # introspection only -- never fail the run for this
        print("[victim] (pool introspection unavailable: {})".format(exc))

    return 0


if __name__ == "__main__":
    sys.exit(main())
