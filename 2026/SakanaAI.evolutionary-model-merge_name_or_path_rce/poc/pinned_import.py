"""Import the pinned evomerge `video_blip` module for this reproduction.

Why this helper exists
----------------------
`evomerge/__init__.py` re-exports `evomerge.models`, and
`evomerge/models/causallm.py` starts with `from vllm import LLM, SamplingParams`
(pyproject.toml pins a GPU-only fork of vLLM).  That import cannot succeed on a
CPU reproduction host, and it has nothing to do with the audited path.

This helper therefore registers the pinned package *directory* and lets every
real sub-package `__init__` below it run normally.

Nothing on the audited path is replaced: `configuration_video_blip.py`,
`modeling_video_blip.py` and `processing_video_blip.py` are loaded from
`evolutionary-model-merge-09aff543/` exactly as pinned at commit
09aff543dd2ae966b3dfe457b750563ab063eb03 (codeload tarball snapshot).
"""

import importlib
import pathlib
import sys
import types

UPSTREAM_SRC = pathlib.Path(__file__).resolve().parent / "evolutionary-model-merge-09aff543"


def load_video_blip():
    """Return the pinned `evomerge.modules.heron.video_blip` module."""
    src = str(UPSTREAM_SRC)
    if src not in sys.path:
        sys.path.insert(0, src)
    if "evomerge" not in sys.modules:
        package = types.ModuleType("evomerge")
        package.__path__ = [str(UPSTREAM_SRC / "evomerge")]
        sys.modules["evomerge"] = package
    return importlib.import_module("evomerge.modules.heron.video_blip")
