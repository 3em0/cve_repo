#!/usr/bin/env python
"""The same consumption point, stopped right after the nested config is built.

`VideoBlipConfig.from_pretrained(<model package>)` runs the nested

    AutoConfig.from_pretrained(text_config["_name_or_path"], trust_remote_code=True)

call at `configuration_video_blip.py:387` and returns.  It is used for the
"remote reference" case: there the named repository is a real Hub checkpoint
whose text encoder config describes a 7B model, so building the full model would
need tens of GB.  The code that is fetched and executed is the same either way.

usage: python victim_config_only.py <model package directory>
"""

import sys

from pinned_import import load_video_blip


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python victim_config_only.py <model package directory>")
        return 2

    model_path = sys.argv[1]
    video_blip = load_video_blip()

    print(f"[victim] loading model package (config only): {model_path}")
    config = video_blip.VideoBlipConfig.from_pretrained(model_path)

    print(f"[victim] text_config class : {type(config.text_config).__name__}")
    print(f"[victim] text_config source: {config.text_config._name_or_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
