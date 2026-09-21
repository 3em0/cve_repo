#!/usr/bin/env python3
"""Drive A1111 for a1111.extra_networks_filename_xss.

Victim action: start the WebUI and open it in a browser.  The extra-networks
card HTML for every registered page is produced by interface.load
(modules/ui_extra_networks.py:788), so the card -- and therefore the filename --
is in the DOM without any click.

Never imports the project under test.  Nothing is injected into the page by this
script; the only attacker-controlled input is the NAME of a file on disk.
"""
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:7860"
EVIDENCE = pathlib.Path("/evidence")
WATCHED_OPTION = "samples_filename_pattern"
TOKEN = "MBE2E_XSS"
# the payload marks the DOM with "W" + the HTTP status of its same-origin POST
PRIV_OK = "W200"


def api_get(path, timeout=60):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode())


def wait_up(deadline_s=900):
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        try:
            if api_get("/sdapi/v1/sd-models", timeout=20)[0] == 200:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def option_value():
    try:
        return api_get("/sdapi/v1/options")[1].get(WATCHED_OPTION)
    except Exception:
        return None


def browse(seconds, trace_path=None):
    from playwright.sync_api import sync_playwright
    seen = set()
    with sync_playwright() as pw:
        b = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = b.new_context(viewport={"width": 1440, "height": 900})
        if trace_path:
            ctx.tracing.start(screenshots=True, snapshots=True, sources=False)
        page = ctx.new_page()
        try:
            page.goto(BASE + "/", wait_until="domcontentloaded", timeout=120000)
        except Exception:
            pass
        t0 = time.time()
        while time.time() - t0 < seconds:
            try:
                v = page.evaluate("document.documentElement.getAttribute('data-mbe2e')")
                if v:
                    seen.add(v)
            except Exception:
                break
            time.sleep(0.25)
        if trace_path:
            try:
                ctx.tracing.stop(path=trace_path)
            except Exception:
                pass
        try:
            b.close()
        except Exception:
            pass
    return sorted(seen)


def phase(name, lora_dir, seconds, trace):
    up = wait_up()
    before = option_value()
    seen = browse(seconds, trace)
    after = option_value()
    files = sorted(str(p.name) for p in pathlib.Path(lora_dir).rglob("*.safetensors"))
    res = {
        "phase": name,
        "product_reachable": up,
        "lora_files": files,
        "lora_file_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(pathlib.Path(lora_dir).rglob("*.safetensors"))},
        "dom_markers": seen,
        "option_before": before,
        "option_after": after,
        "option_rewritten_by_page": after == TOKEN and before != TOKEN,
    }
    (EVIDENCE / f"phase_{name}.json").write_text(
        json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(res, indent=2, sort_keys=True))
    return res


def merge():
    neg = json.loads((EVIDENCE / "phase_neg.json").read_text())
    pos = json.loads((EVIDENCE / "phase_pos.json").read_text())
    xss = any(m.startswith("W") for m in pos["dom_markers"])
    priv = PRIV_OK in pos["dom_markers"]
    ok = xss and priv and not neg["dom_markers"]
    result = {
        "root_key": "a1111.extra_networks_filename_xss",
        "product": "AUTOMATIC1111/stable-diffusion-webui",
        "product_commit": os.environ.get("A1111_COMMIT", ""),
        "product_commit_verified": os.environ.get("MBE2E_PIN_OK", ""),
        "source_tree_sha256": os.environ.get("MBE2E_TREEHASH", ""),
        "drive_method": "playwright",
        "negative": neg,
        "positive": pos,
        "xss_executed_in_origin": xss,
        "privileged_same_origin_api_effect": priv,
        "privileged_api_call": "POST /sdapi/v1/refresh-checkpoints from the page origin; the DOM marker carries the HTTP status the product returned",
        "verdict": "E2_product_e2e" if ok else "FAILED",
        "sink_effect": "browser_token" if xss else "none",
    }
    blob = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (EVIDENCE / "result.json").write_text(blob, encoding="utf-8")
    sys.stdout.write(blob)
    return 0 if ok else 1


if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else "merge"
    if a == "neg":
        phase("neg", "/app/webui/models/Lora_neg", 60, None)
        sys.exit(0)
    if a == "pos":
        phase("pos", "/app/webui/models/Lora_pos", 90, str(EVIDENCE / "browser_trace.zip"))
        sys.exit(0)
    sys.exit(merge())
