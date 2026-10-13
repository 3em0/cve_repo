"""Second file of repository B.

`evomerge/modules/heron/video_blip/modeling_video_blip.py:1960-1961` (commit
09aff543) builds the text encoder with

    language_model = AutoModelForCausalLM.from_config(
        config.text_config, trust_remote_code=True, torch_dtype=torch.float16
    )

and `config.text_config` is the configuration that came from the nested
`_name_or_path` field.  Its `auto_map["AutoModelForCausalLM"]` therefore makes
transformers fetch and import this file as well.  Like the configuration file,
it is harmless: it only prints one line and defines a standard GPT-NeoX model.
"""

from transformers import GPTNeoXForCausalLM

print()
print("[PoC] modeling file from repository B imported too (modeling_video_blip.py:1961)")
print()


class PoCStableLMModel(GPTNeoXForCausalLM):
    """Causal LM of B - a plain GPT-NeoX model so the victim's load completes."""
