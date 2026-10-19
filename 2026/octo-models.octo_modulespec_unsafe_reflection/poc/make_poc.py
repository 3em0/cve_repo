#!/usr/bin/env python3
"""Build an Octo checkpoint the way Octo itself writes one, then derive the two
ModuleSpec variants that the report compares.

base     : written by OctoModel.from_config(...).save_pretrained(0, ...)
positive : heads.action -> logging:FileHandler(..., delay=false)  -> opens the sink file
negative : heads.action -> logging:FileHandler(..., delay=true)   -> opens nothing

The only byte difference between positive and negative is model.heads.action
.kwargs.delay.  No .py file, no plugin and no pickle sidecar is placed inside
any checkpoint directory.
"""
import hashlib
import json
import shutil
import sys
import traceback
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
CKPTS = HERE / "checkpoints"
BASE = CKPTS / "octo-checkpoint-base"
POS = CKPTS / "octo-checkpoint-positive"
NEG = CKPTS / "octo-checkpoint-negative"

SINK = "/out/octo_modulespec_sink_marker"


def model_config():
    """Same layout as scripts/configs/config.py:get_model_config('dummy')."""
    from octo.model.components.action_heads import MSEActionHead
    from octo.model.components.tokenizers import ImageTokenizer
    from octo.model.components.transformer import common_transformer_sizes
    from octo.model.components.vit_encoders import SmallStem16
    from octo.utils.spec import ModuleSpec

    token_embedding_size, transformer_kwargs = common_transformer_sizes("dummy")
    return dict(
        observation_tokenizers=dict(
            image=ModuleSpec.create(
                ImageTokenizer,
                obs_stack_keys=["image_.*"],
                task_stack_keys=["image_.*"],
                task_film_keys=["language_instruction"],
                encoder=ModuleSpec.create(SmallStem16, use_film=True),
            )
        ),
        task_tokenizers=dict(),
        heads=dict(
            action=ModuleSpec.create(
                MSEActionHead,
                action_horizon=1,
                action_dim=7,
                readout_key="obs",
            )
        ),
        readouts=dict(),
        token_embedding_size=token_embedding_size,
        transformer_kwargs=transformer_kwargs,
        max_horizon=10,
        use_correct_attention=True,
    )


def example_batch():
    """A syntactically complete Octo batch: one camera, window of 2, 7-d actions."""
    rng = np.random.default_rng(0)
    batch, window = 2, 2
    return {
        "observation": {
            "image_primary": rng.random((batch, window, 256, 256, 3), dtype=np.float32),
            "timestep_pad_mask": np.ones((batch, window), dtype=bool),
            "pad_mask": np.ones((batch, window), dtype=bool),
        },
        "task": {
            "language_instruction": np.zeros((batch, 512), dtype=np.float32),
            "pad_mask_dict": {"language_instruction": np.ones((batch,), dtype=bool)},
        },
        "action": np.zeros((batch, window, 7), dtype=np.float32),
        "pad_mask_dict": {"action": np.ones((batch, window), dtype=bool)},
    }


def head_spec(delay):
    return {
        "module": "logging",
        "name": "FileHandler",
        "args": [],
        "kwargs": {
            "filename": SINK,
            "mode": "w",
            "encoding": "utf-8",
            "delay": delay,
            "errors": None,
        },
    }


def build_model(wrapper, batch, stats):
    from octo.model.octo_model import OctoModel

    try:
        model = OctoModel.from_config(wrapper, batch, dataset_statistics=stats)
        print("  model: OctoModel.from_config() initialised the dummy transformer")
        return model
    except Exception:
        last = traceback.format_exc(limit=1).strip().splitlines()[-1]
        print(f"  model: from_config() failed ({last});")
        print("         using an OctoModel with a placeholder parameter tree")

    from octo.model.octo_module import OctoModule

    return OctoModel(
        module=OctoModule.create(**wrapper["model"]),
        params={"placeholder": np.zeros(1, dtype=np.float32)},
        text_processor=None,
        example_batch=batch,
        config=wrapper,
        dataset_statistics=stats,
    )


def save(model):
    try:
        model.save_pretrained(0, str(BASE))
        return
    except AttributeError as exc:
        if "jax_coordination_service" not in str(exc):
            raise
    # orbax 0.2.4 probes jax.config.jax_coordination_service, a flag that jax
    # 0.4.20 does not define.  The probe only decides whether to save at a
    # multi-host preemption sync point; for a single-process local save it can
    # be answered with False.
    from orbax.checkpoint.checkpoint_manager import CheckpointManager

    CheckpointManager.reached_preemption = lambda self, step: False
    model.save_pretrained(0, str(BASE))
    print("  note: patched CheckpointManager.reached_preemption -> False")
    print("        (orbax 0.2.4 probes a jax flag absent from jax 0.4.20)")


def write_base():
    cfg = model_config()
    batch = example_batch()
    stats = {
        "action": {
            "mean": np.zeros((1, 7), dtype=np.float32),
            "std": np.ones((1, 7), dtype=np.float32),
        }
    }
    wrapper = {"model": cfg, "text_processor": None}

    shutil.rmtree(BASE, ignore_errors=True)
    BASE.mkdir(parents=True)

    model = build_model(wrapper, batch, stats)
    save(model)
    print(f"  wrote {BASE}")


def derive(name, delay):
    dst = CKPTS / name
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(BASE, dst)
    cfg_path = dst / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["model"]["heads"]["action"] = head_spec(delay)
    cfg_path.write_text(json.dumps(cfg))
    return cfg_path


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    print("[1/3] base checkpoint, written by OctoModel.save_pretrained(0, ...)")
    write_base()

    print("[2/3] positive: heads.action -> logging:FileHandler(delay=False)")
    pos_cfg = derive("octo-checkpoint-positive", False)

    print("[3/3] negative: heads.action -> logging:FileHandler(delay=True)")
    neg_cfg = derive("octo-checkpoint-negative", True)

    print()
    for p in (BASE, POS, NEG):
        files = sorted(f.relative_to(p).as_posix() for f in p.rglob("*") if f.is_file())
        print(f"{p.name}: {len(files)} files")
        for f in files:
            print(f"  {f}")
    print()
    print(f"sha256 {pos_cfg.relative_to(CKPTS)} = {sha256(pos_cfg)}")
    print(f"sha256 {neg_cfg.relative_to(CKPTS)} = {sha256(neg_cfg)}")
    print()
    print("sink path in both configs:", SINK)
    return 0


if __name__ == "__main__":
    sys.exit(main())
