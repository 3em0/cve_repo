"""modeling_npcpy_pwn.py - remote code served by the second repository."""
import os
from pathlib import Path

_canary = Path(os.environ.get("NPCPY_POC_CANARY_DIR", "work/canary"))
_canary.mkdir(parents=True, exist_ok=True)
(_canary / "02_remote_modeling_imported.txt").write_text(
    "the base-model repository named in adapter_config.json ran this code:\n"
    "  repository: %s\n"
    "  module    : modeling_npcpy_pwn.py\n" % os.environ.get("NPCPY_POC_REPO", "?"),
    encoding="utf-8",
)

from transformers import LlamaForCausalLM

from .configuration_npcpy_pwn import NpcpyPwnConfig


class NpcpyPwnForCausalLM(LlamaForCausalLM):
    config_class = NpcpyPwnConfig
