#!/usr/bin/env python3
"""Drive AUTOMATIC1111 as an ordinary user for root a1111.safetensors_yaml_target.

This script NEVER imports the project under test.  It talks to the already
running webui over its own public HTTP API on 127.0.0.1:7860, exactly the way a
user (or any Civitai-style model manager) selects a checkpoint from the
dropdown:

    GET  /sdapi/v1/sd-models          -- list what the product found on disk
    POST /sdapi/v1/options            -- {"sd_model_checkpoint": "<title>"}

The negative control runs FIRST, from a package that is byte-identical except
for the artifact-controlled `model.target` string in the sidecar YAML.
"""
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:7860"
CANARY = pathlib.Path("/out/pwned_by_a1111_yaml_target")
EXPECT_TOKEN = "MBE2E-CANARY-a1111-yaml-target-v1"
EVIDENCE = pathlib.Path("/evidence")
PRODUCT_LOG = EVIDENCE / "logs" / "product_stdout.log"
MODELS = pathlib.Path("/app/webui/models/Stable-diffusion")


def http(method, path, payload=None, timeout=600):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", "replace")
        return r.status, body


def wait_up(deadline_s=900):
    t0 = time.time()
    last = ""
    while time.time() - t0 < deadline_s:
        try:
            st, body = http("GET", "/sdapi/v1/sd-models", timeout=30)
            if st == 200:
                return json.loads(body)
        except Exception as e:  # server not listening yet
            last = f"{type(e).__name__}: {e}"
        time.sleep(3)
    raise SystemExit(f"product never became reachable: {last}")


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def canary_state():
    if not CANARY.exists():
        return {"present": False, "content": None, "sha256": None}
    raw = CANARY.read_bytes()
    return {
        "present": True,
        "content": raw.decode("utf-8", "replace").strip(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def log_text():
    try:
        return PRODUCT_LOG.read_text("utf-8", "replace")
    except Exception:
        return ""


def select(models, marker):
    for m in models:
        if marker in (m.get("filename") or ""):
            return m
    raise SystemExit(f"product did not list a checkpoint under {marker}: "
                     f"{[m.get('filename') for m in models]}")


def main():
    steps = []
    models = wait_up()
    listed = sorted((m.get("title") or "") for m in models)
    steps.append({"step": "list_models", "count": len(models)})

    neg = select(models, "/mbe2e_neg/")
    pos = select(models, "/mbe2e_pack/")

    pre = canary_state()

    st_neg, _ = http("POST", "/sdapi/v1/options",
                     {"sd_model_checkpoint": neg["title"]})
    time.sleep(2)
    after_neg = canary_state()
    steps.append({"step": "select_negative", "http": st_neg,
                  "canary_after": after_neg["present"]})

    st_pos, _ = http("POST", "/sdapi/v1/options",
                     {"sd_model_checkpoint": pos["title"]})
    time.sleep(2)
    after_pos = canary_state()
    steps.append({"step": "select_positive", "http": st_pos,
                  "canary_after": after_pos["present"]})

    text = log_text()
    result = {
        "root_key": "a1111.safetensors_yaml_target",
        "product": "AUTOMATIC1111/stable-diffusion-webui",
        "product_commit": os.environ.get("A1111_COMMIT", ""),
        "product_commit_verified": os.environ.get("MBE2E_PIN_OK", ""),
        "drive_method": "http",
        "listed_checkpoints": listed,
        "artifact_sha256": {
            str(p.relative_to(MODELS)): sha256(p)
            for p in sorted(MODELS.rglob("*")) if p.is_file()
        },
        "canary_path": str(CANARY),
        "canary_before_any_selection": pre,
        "canary_after_negative_selection": after_neg,
        "canary_after_positive_selection": after_pos,
        "negative_sidecar_was_read": "Creating model from config:" in text and "models/Stable-diffusion/mbe2e_neg/model.yaml" in text,
        "positive_sidecar_was_read": "Creating model from config:" in text and "models/Stable-diffusion/mbe2e_pack/model.yaml" in text,
        "http_status": {"select_negative": st_neg, "select_positive": st_pos},
        "steps": steps,
    }

    verdict_ok = (
        pre["present"] is False
        and after_neg["present"] is False
        and after_pos["present"] is True
        and after_pos["content"] == EXPECT_TOKEN
        and result["negative_sidecar_was_read"]
        and result["positive_sidecar_was_read"]
    )
    result["verdict"] = "E2_product_e2e" if verdict_ok else "FAILED"
    result["sink_effect"] = "canary_file" if after_pos["present"] else "none"

    blob = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (EVIDENCE / "result.json").write_text(blob, encoding="utf-8")
    sys.stdout.write(blob)
    return 0 if verdict_ok else 1


if __name__ == "__main__":
    sys.exit(main())
