#!/usr/bin/env python3
"""Drive AUTOMATIC1111 as an ordinary user for a1111.sshs_hash_xss_staged_rce.

The victim's whole action is: start the WebUI and open it in a browser.  This
script does exactly that with a real headless Chromium (Playwright) against the
real product on 127.0.0.1:7860.  It NEVER imports the project under test and it
never injects any script of its own into the page -- everything that happens in
the page comes from the safetensors metadata field.

Phases (selected by argv[1]):
  neg    benign package only -- nothing must fire
  pos    attacker package    -- XSS -> product's own extension installer ->
                                stage-1 exec -> product restarts itself ->
                                stage-2 import
  merge  combine the phase files into result.json
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
EVIDENCE = pathlib.Path("/evidence")
PRODUCT_LOG = EVIDENCE / "logs" / "product_stdout.log"
EXT_DIR = pathlib.Path("/app/webui/extensions")

STAGE1 = pathlib.Path("/out/pwned_by_a1111_sshs_stage1")
STAGE2 = pathlib.Path("/out/pwned_by_a1111_sshs_stage2")
TOK1 = "MBE2E-CANARY-a1111-sshs-stage1-v1"
TOK2 = "MBE2E-CANARY-a1111-sshs-stage2-v1"

MILESTONES = ["XSS_RAN", "INSTALL_CLICKED", "INSTALLED", "INSTALL_UNCONFIRMED",
              "RESTART_CLICKED", "RELOAD_CLICKED", "NO_CONTROLS", "NO_RESTART_CONTROL"]


def wait_up(deadline_s=900):
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        try:
            req = urllib.request.Request(BASE + "/sdapi/v1/sd-models")
            with urllib.request.urlopen(req, timeout=20) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def canary(p):
    if not p.exists():
        return {"present": False, "content": None}
    raw = p.read_bytes()
    return {"present": True, "content": raw.decode("utf-8", "replace").strip(),
            "sha256": hashlib.sha256(raw).hexdigest()}


def ext_listing():
    if not EXT_DIR.exists():
        return []
    return sorted(x.name for x in EXT_DIR.iterdir())


def log_text():
    try:
        return PRODUCT_LOG.read_text("utf-8", "replace")
    except Exception:
        return ""


def run_browser(phase, watch_seconds, trace_path=None):
    from playwright.sync_api import sync_playwright
    seen = set()
    console = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        if trace_path:
            ctx.tracing.start(screenshots=True, snapshots=True, sources=False)
        page = ctx.new_page()
        page.on("console", lambda m: console.append(m.type + ":" + m.text[:200]))
        try:
            page.goto(BASE + "/", wait_until="domcontentloaded", timeout=120000)
        except Exception as e:
            console.append("goto:" + type(e).__name__)
        t0 = time.time()
        while time.time() - t0 < watch_seconds:
            try:
                v = page.evaluate("document.documentElement.getAttribute('data-mbe2e')")
                if v:
                    seen.add(v)
            except Exception:
                # the product restarts itself mid-flight; the page dies with it
                break
            if "RESTART_CLICKED" in seen or "RELOAD_CLICKED" in seen:
                break
            time.sleep(0.25)
        if trace_path:
            try:
                ctx.tracing.stop(path=trace_path)
            except Exception:
                pass
        try:
            browser.close()
        except Exception:
            pass
    return sorted(seen), console


def phase_neg():
    up = wait_up()
    seen, _ = run_browser("neg", 60)
    res = {
        "phase": "neg",
        "product_reachable": up,
        "dom_milestones": seen,
        "stage1": canary(STAGE1),
        "stage2": canary(STAGE2),
        "extensions_dir": ext_listing(),
    }
    (EVIDENCE / "phase_neg.json").write_text(
        json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


def phase_pos():
    up = wait_up()
    before = {"stage1": canary(STAGE1), "stage2": canary(STAGE2),
              "extensions_dir": ext_listing()}
    seen, console = run_browser("pos", 300, trace_path=str(EVIDENCE / "browser_trace.zip"))

    after_browser = {"stage1": canary(STAGE1), "extensions_dir": ext_listing()}

    # the XSS pressed "Apply and restart UI"; webui.sh relaunches the process.
    restarted = False
    t0 = time.time()
    while time.time() - t0 < 600:
        if log_text().count("Running on local URL") >= 2:
            restarted = True
            break
        time.sleep(3)
    if restarted:
        wait_up(600)
    time.sleep(5)

    text = log_text()
    res = {
        "phase": "pos",
        "product_reachable": up,
        "before": before,
        "dom_milestones": seen,
        "console_messages": len(console),
        "after_browser": after_browser,
        "product_restarted_itself": restarted,
        "stage1": canary(STAGE1),
        "stage2": canary(STAGE2),
        "extensions_dir_final": ext_listing(),
        "installer_ran_in_product_log": "Installing extension" in text or "mbe2e_lora" in text,
    }
    (EVIDENCE / "phase_pos.json").write_text(
        json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


def phase_merge():
    neg = json.loads((EVIDENCE / "phase_neg.json").read_text())
    pos = json.loads((EVIDENCE / "phase_pos.json").read_text())
    xss = "XSS_RAN" in pos["dom_milestones"]
    s1 = pos["stage1"]["present"] and pos["stage1"]["content"] == TOK1
    s2 = pos["stage2"]["present"] and pos["stage2"]["content"] == TOK2
    neg_clean = (not neg["dom_milestones"]
                 and not neg["stage1"]["present"]
                 and not neg["stage2"]["present"]
                 and "mbe2e_lora" not in neg["extensions_dir"])

    if xss and s1 and s2 and neg_clean and pos["product_restarted_itself"]:
        verdict, grade = "PASS", "E2_product_e2e"
    elif xss and s1 and neg_clean:
        verdict, grade = "PARTIAL", "E1_product_partial"
    elif xss and neg_clean:
        verdict, grade = "XSS_ONLY", "E1_product_partial"
    else:
        verdict, grade = "FAILED", "blocked"

    result = {
        "root_key": "a1111.sshs_hash_xss_staged_rce",
        "product": "AUTOMATIC1111/stable-diffusion-webui",
        "product_commit": os.environ.get("A1111_COMMIT", ""),
        "product_commit_verified": os.environ.get("MBE2E_PIN_OK", ""),
        "source_tree_sha256": os.environ.get("MBE2E_TREEHASH", ""),
        "drive_method": "playwright",
        "negative": neg,
        "positive": pos,
        "xss_executed_in_origin": xss,
        "stage1_host_exec": s1,
        "stage2_after_restart_import": s2,
        "negative_control_clean": neg_clean,
        "verdict": verdict,
        "achieved_grade": grade,
        "sink_effect": "browser_token" if xss else "none",
    }
    blob = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (EVIDENCE / "result.json").write_text(blob, encoding="utf-8")
    sys.stdout.write(blob)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    ph = sys.argv[1] if len(sys.argv) > 1 else "merge"
    sys.exit({"neg": phase_neg, "pos": phase_pos, "merge": phase_merge}[ph]())
