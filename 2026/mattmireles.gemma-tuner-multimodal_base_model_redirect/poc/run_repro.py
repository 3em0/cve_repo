"""Victim-side driver: run the product's real export CLI over a LoRA adapter.

usage:  python run_repro.py adapter_attack
        python run_repro.py adapter_benign

What happens, in order
----------------------
1. read ``base_model_name_or_path`` out of the adapter package (this string is
   the only attacker-controlled value, and the only difference between the two
   adapter directories built by ``make_poc.py``);
2. start ``mock_hub.py`` on 127.0.0.1:8765 as a stand-in for huggingface.co and
   point the child process at it with ``HF_ENDPOINT`` (the real ``huggingface_hub``
   download path is used, nothing is monkey-patched);
3. run the REAL product entry point -- the ``gemma-macos-tuner export <dir>``
   command from the pinned checkout
   (``gemma_tuner/cli_typer.py:export()`` -> ``core/ops.py:export()`` ->
   ``scripts/export.py:export_model_dir()``), unmodified.  The child first calls
   the project's own ``core/logging.py:init_logging('INFO')`` so the loader's
   own log lines are visible;
4. report which repositories the product contacted (mock-hub request log);
5. read the embedding oracle back out of the exported model and compare it with
   both candidate base repositories.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import torch
from safetensors import safe_open

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
HUB = os.path.join(WORK, "hub")
REQLOG = os.path.join(WORK, "hub_requests.log")
PINNED = os.path.join(HERE, "gemma-tuner-multimodal-ebdcd76d")

CONTROL_REPO = "mbe2e-control/tiny-random-gemma3-base-025"
ATTACK_REPO = "mbe2e-attacker/tiny-random-gemma3-base-075"
CASES = {"adapter_benign": CONTROL_REPO, "adapter_attack": ATTACK_REPO}


def _embedding_tensor(safetensors_path: str):
    """Return (key, tensor) for the text-embedding matrix of a weight file."""
    with safe_open(safetensors_path, framework="pt") as f:
        keys = [k for k in f.keys() if k.endswith("embed_tokens.weight")]
        if not keys:
            raise SystemExit("no embed_tokens.weight in %s" % safetensors_path)
        text_keys = [k for k in keys if "language_model" in k] or keys
        key = text_keys[0]
        return key, f.get_tensor(key)


def _repos_contacted(log_path: str):
    repos = set()
    if not os.path.exists(log_path):
        return repos
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            path = parts[1]
            seg = path.split("/resolve/")[0].strip("/")
            if seg.count("/") >= 1 and not seg.startswith("api"):
                repos.add(seg)
    return repos


def main() -> int:
    case = sys.argv[1] if len(sys.argv) > 1 else "adapter_attack"
    if case not in CASES:
        raise SystemExit("usage: python run_repro.py adapter_attack|adapter_benign")

    adapter_dir = os.path.join(WORK, case)
    adapter_arg = os.path.join("work", case)  # relative, the way a user types it
    out_dir = adapter_dir + "-export"
    cfg_path = os.path.join(adapter_dir, "adapter_config.json")
    if not os.path.isfile(cfg_path):
        raise SystemExit("missing %s -- run `python make_poc.py` first" % cfg_path)

    with open(cfg_path, encoding="utf-8") as f:
        adapter_cfg = json.load(f)
    pointer = adapter_cfg["base_model_name_or_path"]

    print("[driver] adapter pointer: %s" % pointer)

    # clean slate so the evidence belongs to this run only: request log,
    # previous export output, and the per-case Hub cache (otherwise a cached
    # blob would hide the second-hop fetch from the request log)
    if os.path.exists(REQLOG):
        os.remove(REQLOG)
    shutil.rmtree(out_dir, ignore_errors=True)
    hf_home = os.path.join(WORK, "hf-home-" + case)
    shutil.rmtree(hf_home, ignore_errors=True)

    import mock_hub

    mock_hub.start_server(port=8765, hub_root=HUB, request_log=REQLOG)
    print("[driver] mock Hub: work/hub on 127.0.0.1:8765 (for huggingface.co)")
    print("[driver] Hub requests are logged to work/hub_requests.log")

    env = os.environ.copy()
    env["HF_HOME"] = hf_home
    env["HF_ENDPOINT"] = "http://127.0.0.1:8765"
    env["HF_HUB_DISABLE_TELEMETRY"] = "1"
    env["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
    env["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    env["PYTHONPATH"] = PINNED
    env["PYTHONUNBUFFERED"] = "1"
    for var in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_TOKEN"):
        env.pop(var, None)

    print("[driver] running: gemma-macos-tuner export %s" % adapter_arg)
    print("-" * 72)
    # The child runs the product's own CLI.  It first calls the project's own
    # logging initializer so the loader's log lines are visible; httpx/httpcore
    # are then set to WARNING so those lines fit on one screen -- the complete
    # HTTP request log is kept in work/hub_requests.log and printed below.
    child = (
        "import logging, runpy, sys\n"
        "from gemma_tuner.core.logging import init_logging\n"
        "init_logging('INFO')\n"
        "logging.getLogger('httpx').setLevel(logging.WARNING)\n"
        "logging.getLogger('httpcore').setLevel(logging.WARNING)\n"
        "sys.argv = ['gemma-macos-tuner', 'export', %r]\n"
        "runpy.run_module('gemma_tuner.cli_typer', run_name='__main__')\n"
    ) % adapter_arg
    # Tee the product's console output to work/run_<case>.log: the terminal
    # still shows it live, and the log keeps the product's own statements
    # ("Loading base model: ...", "Loaded multimodal base model ... via ...").
    log_path = os.path.join(WORK, "run_%s.log" % case)
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen([sys.executable, "-c", child], env=env, cwd=HERE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for raw in proc.stdout:
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            logf.write(raw)
        proc.wait()
    print("-" * 72)
    print("[driver] product CLI exit code: %d" % proc.returncode)
    print("[driver] product output saved to work/run_%s.log" % case)

    repos = _repos_contacted(REQLOG)
    print("[driver] repos contacted: %s"
          % (", ".join(sorted(repos)) if repos else "<none>"))

    export_weights = os.path.join(out_dir, "model.safetensors")
    if not os.path.isfile(export_weights):
        print("[driver] RESULT: export produced no model.safetensors -- see log above")
        return 1

    key, tensor = _embedding_tensor(export_weights)
    oracle = float(tensor[0, 0])
    _, control_t = _embedding_tensor(os.path.join(HUB, *CONTROL_REPO.split("/"),
                                                 "model.safetensors"))
    _, attack_t = _embedding_tensor(os.path.join(HUB, *ATTACK_REPO.split("/"),
                                                 "model.safetensors"))
    is_control = bool(torch.equal(tensor, control_t))
    is_attack = bool(torch.equal(tensor, attack_t))

    print("[driver] oracle: %s @ %s" % (oracle, key))
    print("[driver] weights == control base  (0.25): %s" % is_control)
    print("[driver] weights == attacker base (0.75): %s" % is_attack)

    manifest = os.path.join(out_dir, ".integrity.json")
    if os.path.isfile(manifest):
        print("[driver] manifest source: work\\%s (no base repo recorded)" % case)

    print("=" * 72)
    expected_attack = CASES[case] == ATTACK_REPO
    if expected_attack and is_attack and not is_control and ATTACK_REPO in repos:
        print("RESULT: BASE-MODEL REDIRECT CONFIRMED")
        print("        the adapter's base_model_name_or_path selected the exported")
        print("        weights (fetched %s)." % ATTACK_REPO)
        return 0
    if not expected_attack and is_control and not is_attack:
        print("RESULT: no redirect (negative control) - the benign adapter")
        print("        fetched %s only;" % CONTROL_REPO)
        print("        the attacker repository was never contacted.")
        return 0
    print("RESULT: unexpected outcome (repos contacted=%s, control=%s, attacker=%s)"
          % (sorted(repos), is_control, is_attack))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
