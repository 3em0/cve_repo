"""Start the local mock Hub and then hand the console to FastChat's real CLI.

usage:  python serve_cli_locally.py work/adapter_attack_peft

This is the interactive counterpart of ``run_repro.py``: the mock Hub runs in a
background thread of this process (so the fetch log stays local and no traffic
leaves the machine), and ``fastchat.serve.cli`` -- the pinned, unmodified product
entry point -- is then started in the *same console*, so you can type at its
"Human:" prompt and watch it answer.

Everything the product prints below the ``[local-hub]`` line comes from
``python -m fastchat.serve.cli`` itself.
"""
from __future__ import annotations

import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
HUB = os.path.join(WORK, "hub")
PINNED = os.path.join(HERE, "FastChat-587d5cf")


def main() -> int:
    adapter = sys.argv[1] if len(sys.argv) > 1 else os.path.join("work", "adapter_attack_peft")
    case = os.path.basename(os.path.normpath(adapter))

    os.environ["HF_ENDPOINT"] = "http://127.0.0.1:8765"
    os.environ["HF_HOME"] = os.path.join(WORK, "hf-home-interactive-" + case)
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["TRANSFORMERS_VERBOSITY"] = "error"
    for var in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_TOKEN"):
        os.environ.pop(var, None)
    if PINNED not in sys.path:
        sys.path.insert(0, PINNED)

    import mock_hub

    request_log = os.path.join(WORK, "hub_requests_interactive_%s.log" % case)
    mock_hub.start_server(port=8765, hub_root=HUB, request_log=request_log)
    print("[local-hub] serving work/hub on 127.0.0.1:8765 for huggingface.co")
    print("[local-hub] requests -> work/%s" % os.path.basename(request_log))
    print("[local-hub] starting: python -m fastchat.serve.cli --model-path %s "
          "--device cpu --temperature 0 --max-new-tokens 4" % adapter)
    print("")

    sys.argv = [
        "fastchat.serve.cli",
        "--model-path", adapter,
        "--device", "cpu",
        "--temperature", "0",
        "--max-new-tokens", "4",
        "--style", "simple",
    ]
    runpy.run_module("fastchat.serve.cli", run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
