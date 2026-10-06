#!/usr/bin/env python3
"""verify_poc.py -- drive the REAL ComfyUI stack with the crafted workflow artifact.

Nothing about the product is patched or mocked:
  * real ComfyUI server (python main.py) serves the page and the frontend bundle
  * the real VNCCS custom node is installed at the pinned commit, its extension JS
    is loaded by the page, and its node type is registered
  * the crafted workflow JSON is handed to the page the way a user opens a workflow
    (the frontend's own workflow-open file input, whose handler calls
    app.loadGraphData -- see the "loader" line in the output)
  * a real Chromium renders the page and runs the injected handler

Evidence collected per run:
  * whether VNCCS_EmotionsGenerator was registered and its onConfigure hook installed
  * what readData() put into widget.data.character_name
  * whether the reported sink (renderSettings -> .vnccs-pipe-block .vnccs-pipe-empty)
    actually received the injected <img> element
  * whether that element loaded its src (naturalWidth) or errored
  * whether the inline handler ran (document.documentElement.dataset.mbe2e)

Usage:
  python verify_poc.py --sample ..\\samples\\poc_xss_positive.json --expect fire
  python verify_poc.py --sample ..\\samples\\poc_xss_negative_control.json --expect nofire
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import time
import urllib.request

DOM_SENTINEL = "mbe2e"
ELEMENT_ID = "mbe2e-seq064"

JS_NODE_TYPE_CHECK = """(() => {
  const t = (window.LiteGraph && LiteGraph.registered_node_types)
      ? LiteGraph.registered_node_types['VNCCS_EmotionsGenerator'] : null;
  const exts = Array.isArray(app.extensions) ? app.extensions.map(e => e && e.name) : null;
  return {
    node_type_registered: !!t,
    onconfigure_hook: !!(t && String(t.prototype.onConfigure).includes('_vnccsCharacterGeneratorWidget')),
    extension_registered: exts ? exts.includes('VNCCS.CharacterGenerator') : null,
    extension_names: exts ? exts.filter(n => n && /vnccs/i.test(n)) : null,
  };
})()"""

JS_DIAGNOSTICS = """(() => {
  const out = {nodes: 0};
  const nodes = (app.graph && app.graph._nodes) || [];
  out.nodes = nodes.length;
  out.node_types = nodes.map(x => x.type);
  const n = nodes.find(x => x.type === 'VNCCS_EmotionsGenerator');
  out.sink_node_present = !!n;
  const w = n && n._vnccsCharacterGeneratorWidget;
  out.widget_present = !!w;
  out.node_widget_names = n && n.widgets ? n.widgets.map(x => x.name) : null;
  const wd = n && n.widgets ? n.widgets.find(x => x.name === 'widget_data') : null;
  out.node_widget_data_head = wd ? String(wd.value).slice(0, 64) : null;
  out.character_name = w ? (w.data && w.data.character_name) || null : null;
  const settings = w && w.settingsEl;
  out.settings_reachable = !!settings;
  out.sink_markup_injected = !!(settings && settings.innerHTML.indexOf('%EID%') !== -1);
  out.settings_html_head = settings ? settings.innerHTML.slice(0, 180) : null;
  const img = settings
      ? settings.querySelector('.vnccs-pipe-block .vnccs-pipe-empty img') : null;
  out.sink_img_present = !!img;
  if (img) {
    const raw = img.getAttribute('src') || '';
    out.sink_img_id = img.id || null;
    out.sink_img_src_head = raw.slice(0, 48);
    out.sink_img_src_kind = raw.startsWith('data:') ? 'data-uri' : 'url';
    out.sink_img_complete = img.complete;
    out.sink_img_natural_width = img.naturalWidth;
    out.sink_img_onerror_attr = img.getAttribute('onerror');
  }
  out.dom_sentinel = document.documentElement.dataset.%SENTINEL% || null;
  out.other_emotion_nodes = nodes.filter(x => x.type === 'EmotionGeneratorV2').length;
  out.page_errors = window.__poc_page_errors || [];
  return out;
})()""".replace("%EID%", ELEMENT_ID).replace("%SENTINEL%", DOM_SENTINEL)


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def server_info(base: str):
    try:
        with urllib.request.urlopen(base + "/system_stats", timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"error": type(exc).__name__ + ": " + str(exc)[:120]}


def wait_server(base: str, seconds: int) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        info = server_info(base)
        if "error" not in info:
            return True
        time.sleep(1)
    return False


def line(label, value):
    print("  %-26s %s" % (label + ":", value))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:8188")
    ap.add_argument("--expect", choices=["fire", "nofire", "auto"], default="auto")
    ap.add_argument("--wait-server", type=int, default=180)
    ap.add_argument("--settle", type=float, default=6.0)
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--browser-shot", default=None,
                    help="optional path for a real browser screenshot of the page")
    args = ap.parse_args()

    sample = pathlib.Path(args.sample).resolve()
    if not sample.exists():
        sys.exit("missing sample: %s" % sample)
    expect = args.expect
    if expect == "auto":
        expect = "fire" if "positive" in sample.name else "nofire"

    print("== ComfyUI / VNCCS workflow-artifact check ==")
    line("sample", sample.name)
    line("sha256", sha256(sample))
    if not wait_server(args.base, args.wait_server):
        sys.exit("ComfyUI server not reachable at %s" % args.base)
    info = server_info(args.base)
    line("server", "%s (comfyui %s, python %s)" % (
        args.base,
        (info.get("system") or {}).get("comfyui_version"),
        (info.get("system") or {}).get("python_version", "").split()[0],
    ))
    line("device", ((info.get("devices") or [{}])[0]).get("name"))

    from playwright.sync_api import sync_playwright

    result = {}
    console = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headed,
                                     args=["--disable-gpu", "--disable-gpu-sandbox"])
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        page.on("pageerror", lambda e: console.append("pageerror: " + str(e)[:160]))

        def on_console(msg):
            if msg.type in ("error", "warning"):
                console.append("console.%s: %s" % (msg.type, msg.text[:200]))

        page.on("console", on_console)
        try:
            page.goto(args.base + "/", wait_until="domcontentloaded", timeout=120000)
            page.wait_for_function("window.app && window.app.graph", timeout=120000)
            page.wait_for_function(
                "!!(window.LiteGraph && LiteGraph.registered_node_types &&"
                " LiteGraph.registered_node_types['VNCCS_EmotionsGenerator'])",
                timeout=120000)
            for _ in range(3):
                page.keyboard.press("Escape")
                time.sleep(0.4)
            hooks = page.evaluate(JS_NODE_TYPE_CHECK)
            result.update(hooks)
            line("node type registered", hooks["node_type_registered"])
            line("onConfigure hook", hooks["onconfigure_hook"])
            line("extension registered", hooks["extension_registered"])

            # open the crafted workflow the way the UI does it
            loader = None
            for selector in ("#comfy-file-input", "input[type=file]"):
                if page.locator(selector).count():
                    page.set_input_files(selector, str(sample), timeout=60000)
                    loader = "frontend workflow-open input (%s) -> app.loadGraphData" % selector
                    break
            if loader is None:
                page.evaluate(
                    "async (txt) => { await app.loadGraphData(JSON.parse(txt)); }",
                    sample.read_text(encoding="utf-8"))
                loader = "app.loadGraphData (no file input found in this frontend build)"
            line("loader", loader)
            result["loader"] = loader

            page.wait_for_function(
                "app.graph._nodes.some(n => n.type === 'VNCCS_EmotionsGenerator')",
                timeout=60000)
            time.sleep(args.settle)

            diag = page.evaluate(JS_DIAGNOSTICS)
            result.update(diag)
            if args.browser_shot:
                pathlib.Path(args.browser_shot).parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=args.browser_shot, full_page=False)
            result["page_errors"] = console[:10]
        except Exception as exc:  # noqa: BLE001
            result["driver_error"] = type(exc).__name__ + ": " + str(exc)[:300]
            result["page_errors"] = console[:10]
        finally:
            browser.close()

    print()
    print("== observed in the real page ==")
    line("graph node types", result.get("node_types"))
    line("emotion-studio nodes", result.get("other_emotion_nodes"))
    line("node widgets", result.get("node_widget_names"))
    line("widget_data head", (result.get("node_widget_data_head") or "")[:44])
    line("widget.data.character_name", (result.get("character_name") or "<unset>")[:72])
    line("sink markup injected", result.get("sink_markup_injected"))
    line("sink <img> present", result.get("sink_img_present"))
    if result.get("sink_img_present"):
        line("img id / src kind", "%s / %s" % (result.get("sink_img_id"),
                                               result.get("sink_img_src_kind")))
        line("img src head", result.get("sink_img_src_head"))
        line("img complete", result.get("sink_img_complete"))
        line("img naturalWidth", result.get("sink_img_natural_width"))
        line("img onerror handler", result.get("sink_img_onerror_attr"))
    line("dataset.mbe2e", repr(result.get("dom_sentinel")))
    page_errors = [e for e in (result.get("page_errors") or [])
                   if not e.startswith("console.warning")]
    seen, uniq = set(), []
    for e in page_errors:
        if e not in seen:
            seen.add(e)
            uniq.append(e)
    line("console errors", "%d unique" % len(uniq))
    if uniq and result.get("driver_error"):
        for e in uniq[:3]:
            line("", e[:130])
    if result.get("driver_error"):
        line("driver error", result["driver_error"])

    fired = result.get("dom_sentinel") == "xss"
    if fired:
        observed = "fire"
        verdict = "VULNERABLE -- the inline handler in the workflow field executed"
    elif result.get("sink_img_present") and (result.get("sink_img_natural_width") or 0) > 0:
        observed = "nofire"
        verdict = ("NOT TRIGGERED -- element injected, src loaded, onerror never fired")
    elif not result.get("sink_img_present"):
        observed = "nofire"
        verdict = "NOT TRIGGERED -- no markup reached the sink"
    else:
        observed = "nofire"
        verdict = "NOT TRIGGERED -- element injected but no load event completed in time"

    print()
    line("expected", expect)
    line("observed", observed)
    if observed == expect:
        print("RESULT: AS EXPECTED -- %s" % verdict)
    else:
        print("RESULT: UNEXPECTED (expected %s) -- %s" % (expect, verdict))
    if result.get("driver_error"):
        return 2
    return 0 if observed == expect else 1


if __name__ == "__main__":
    sys.exit(main())
