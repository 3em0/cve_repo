#!/usr/bin/env python3
"""
show_diff.py -- prove the two checkpoints differ in exactly one config leaf.

Loads ckpt/benign.pth and ckpt/malicious.pth the same way robomimic does
(torch.load(..., weights_only=False) -> json.loads(ckpt["config"])), flattens both
embedded configs to leaf paths and reports every differing leaf. Also confirms the
serialized model state and the top-level checkpoint keys are structurally identical,
so the only attacker-controlled difference is the pool_class string.
"""
import json
import sys

import torch


def load_config(path):
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    return ckpt, json.loads(ckpt["config"])


def flatten(node, prefix=""):
    out = {}
    if isinstance(node, dict):
        for key, value in node.items():
            out.update(flatten(value, "{}.{}".format(prefix, key) if prefix else key))
    else:
        out[prefix] = node
    return out


def main():
    benign_ckpt, benign_cfg = load_config("ckpt/benign.pth")
    evil_ckpt, evil_cfg = load_config("ckpt/malicious.pth")

    lb, le = flatten(benign_cfg), flatten(evil_cfg)
    print("embedded config leaf fields : benign={} malicious={}".format(len(lb), len(le)))

    diffs = sorted(k for k in set(lb) | set(le) if lb.get(k, "<absent>") != le.get(k, "<absent>"))
    print("differing config leaf fields: {}".format(len(diffs)))
    for key in diffs:
        print("  field  : {}".format(key))
        print("  benign : {!r}".format(lb.get(key)))
        print("  evil   : {!r}".format(le.get(key)))

    bkeys = set(benign_ckpt["model"]["nets"].keys())
    ekeys = set(evil_ckpt["model"]["nets"].keys())
    print("model state_dict keys identical : {} ({} tensors)".format(bkeys == ekeys, len(bkeys)))
    print("top-level ckpt keys identical   : {}".format(
        sorted(benign_ckpt.keys()) == sorted(evil_ckpt.keys())))

    ok = len(diffs) == 1 and diffs[0].endswith("core_kwargs.pool_class")
    print("\nRESULT: single attacker-controlled field = {}".format(ok))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
