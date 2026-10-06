#!/usr/bin/env python3
"""
victim_weights_only.py -- show that the config-JSON eval() sink is independent of
the pickle sink.

robomimic's own loader (FileUtils.load_dict_from_checkpoint) calls
torch.load(..., weights_only=False), which is itself an arbitrary-pickle execution
sink. This script instead loads the same artifact with weights_only=True -- torch's
restricted unpickler, which refuses arbitrary pickle globals -- and then passes the
resulting plain dictionary to the same public entry point through its ckpt_dict=
parameter.

The embedded config is ordinary JSON text, so it survives the restricted loader
unmodified, and eval(pool_class) still fires during network construction. In other
words: hardening the pickle layer alone does not close this hole.
"""
import sys

import torch

import robomimic.utils.file_utils as FileUtils


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "ckpt/malicious.pth"

    print("[victim] torch.load({!r}, weights_only=True)".format(path))
    ckpt_dict = torch.load(path, map_location="cpu", weights_only=True)
    print("[victim] restricted load OK, keys: {}".format(",".join(sorted(ckpt_dict.keys()))))
    print("[victim] ckpt_dict['config'] type = {} (plain JSON text)".format(
        type(ckpt_dict["config"]).__name__))

    print("[victim] FileUtils.policy_from_checkpoint(ckpt_dict=...)")
    policy, _ = FileUtils.policy_from_checkpoint(
        ckpt_dict=ckpt_dict, device=torch.device("cpu"))

    print("[victim] returned : {}".format(type(policy).__name__))
    return 0


if __name__ == "__main__":
    sys.exit(main())
