#!/usr/bin/env python3
"""Victim-side loader: consume a model directory exactly the way
ThunderKittens' based demo consumes a Hugging Face model.

    python run_load.py <model_dir>

Only GPTLMHeadModel.from_pretrained_hf() is called - the payload dispatch
happens inside model construction, before any weight file is read.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "ThunderKittens-cb21f34", "demos", "based")
sys.path.insert(0, SRC)

from train.src.models.gpt import GPTLMHeadModel  # noqa: E402

model_dir = sys.argv[1]
print(f"[*] victim: GPTLMHeadModel.from_pretrained_hf({model_dir!r})")
print("[*] config.json parse + model construction start (no weights read yet)")
model = GPTLMHeadModel.from_pretrained_hf(model_dir)
print(f"[+] construction returned: {type(model).__name__}")
