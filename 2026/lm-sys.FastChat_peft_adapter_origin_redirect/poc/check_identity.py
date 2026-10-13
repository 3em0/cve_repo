"""Read the loaded weights back out of the product's own model loader.

usage:  python check_identity.py

This drives ``fastchat.model.model_adapter.load_model()`` -- the exact function
``fastchat.serve.cli`` calls from ``chat_loop()`` (fastchat/serve/inference.py:361)
-- once per adapter package, and reads two values out of the model object that
comes back:

* ``...embed_tokens.weight[0,0]``: the measurement oracle built by ``make_poc.py``
  (0.25 in the control repository, 0.75 in the attacker repository).  The adapter's
  own LoRA tensors are all zero, so this value can only come from the base
  repository the adapter pointed at.
* ``model.config._name_or_path``: the repository id ``transformers`` recorded when
  it resolved the base model.

The CLI run in ``run_repro.py`` is the primary evidence (it is the real product
entry point); this script is the second, independent reading of the same call.
"""
from __future__ import annotations

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
HUB = os.path.join(WORK, "hub")
REQLOG = os.path.join(WORK, "hub_requests_identity.log")
PINNED = os.path.join(HERE, "FastChat-587d5cf")
if PINNED not in sys.path:
    sys.path.insert(0, PINNED)

CONTROL_REPO = "mbe2e-control/fastchat-base"
ATTACK_REPO = "mbe2e-attacker/fastchat-base"
CONTROL_ORACLE = 0.25
ATTACK_ORACLE = 0.75
CASES = [
    ("adapter_benign_peft", CONTROL_REPO, CONTROL_ORACLE),
    ("adapter_attack_peft", ATTACK_REPO, ATTACK_ORACLE),
]


def embedding_oracle(model):
    """Return (parameter name, value) of embed_tokens.weight[0,0]."""
    for name, param in model.named_parameters():
        if name.endswith("embed_tokens.weight"):
            return name, float(param.detach()[0, 0])
    raise SystemExit("no embed_tokens.weight in the loaded model")


def main() -> int:
    import mock_hub

    os.environ["HF_ENDPOINT"] = "http://127.0.0.1:8765"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["TRANSFORMERS_VERBOSITY"] = "error"
    for var in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_TOKEN"):
        os.environ.pop(var, None)

    if os.path.exists(REQLOG):
        os.remove(REQLOG)
    mock_hub.start_server(port=8765, hub_root=HUB, request_log=REQLOG)
    print("mock Hub : work/hub on 127.0.0.1:8765 (stands in for huggingface.co)")
    print("caller   : fastchat.model.model_adapter.load_model(..., device='cpu')")
    print("           (the same call fastchat.serve.cli makes in chat_loop)")

    import fastchat.model.model_adapter as model_adapter

    results = []
    for case, expected_repo, expected_oracle in CASES:
        adapter_dir = os.path.join(WORK, case)
        hf_home = os.path.join(WORK, "hf-home-identity-" + case)
        shutil.rmtree(hf_home, ignore_errors=True)
        os.environ["HF_HOME"] = hf_home

        model, tokenizer = model_adapter.load_model(adapter_dir, device="cpu")
        name, value = embedding_oracle(model)
        results.append((case, expected_repo, expected_oracle, value, model, tokenizer))

        print("")
        print("adapter package      : work/%s" % case)
        print("loaded model class   : %s" % type(model).__name__)
        print("config._name_or_path : %s" % model.config._name_or_path)
        print("tokenizer name/path  : %s" % tokenizer.name_or_path)
        print("%s[0,0] = %s" % (name, value))
        print("expected from %s : %s" % (expected_repo, expected_oracle))

    print("")
    print("=" * 72)
    ok = True
    for case, expected_repo, expected_oracle, value, model, _tok in results:
        good = (value == expected_oracle and model.config._name_or_path == expected_repo)
        ok = ok and good
        print("%-22s oracle=%-5s repo=%-30s %s"
              % (case, value, model.config._name_or_path,
                 "matches" if good else "MISMATCH"))
    print("=" * 72)
    if ok:
        print("RESULT: the weights in memory come from the repository each")
        print("        adapter package named -- 0.75 from %s," % ATTACK_REPO)
        print("        0.25 from %s." % CONTROL_REPO)
        return 0
    print("RESULT: unexpected identity")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
