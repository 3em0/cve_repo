#!/usr/bin/env python
"""The victim's normal operation, using the pinned source.

`evomerge/models/heron_v1.py` (commit 09aff543) loads a video_blip checkpoint with

    VideoBlipForConditionalGeneration.from_pretrained(
        model_path, ignore_mismatched_sizes=True, **model_kwargs
    )

and `evaluate.py` reaches the same call through `configs/vlm/heron-v1.yaml`
(`model.model_path`) and `evomerge.utils.instantiate_from_config`.  This script
performs exactly that call with the pinned code; nothing is extracted or stubbed.

usage: python victim_load.py <model package directory>
"""

import sys

from pinned_import import load_video_blip


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python victim_load.py <model package directory>")
        return 2

    model_path = sys.argv[1]
    video_blip = load_video_blip()

    print(f"[victim] loading model package: {model_path}")
    model = video_blip.VideoBlipForConditionalGeneration.from_pretrained(
        model_path, ignore_mismatched_sizes=True
    )

    print(f"[victim] model class          : {type(model).__name__}")
    print(f"[victim] text_config class    : {type(model.config.text_config).__name__}")
    print(f"[victim] text_config source   : {model.config.text_config._name_or_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
