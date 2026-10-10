# Cross-validation image for the minions LoRA base-model-redirect PoC.
# Base image already pins torch 2.3.1+cpu / transformers 4.47.0; this layer
# adds only peft (adapter parsing) and tiktoken (minions.usage import).
FROM showo-llmredirect-poc:1
RUN pip install --no-cache-dir peft==0.11.1 tiktoken
