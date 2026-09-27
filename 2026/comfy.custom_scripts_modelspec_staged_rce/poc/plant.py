#!/usr/bin/env python3
"""Set up the victim environment before the product starts.

ATTACKER: copies two .safetensors files into models/loras/. That is the whole
          attacker capability.
VICTIM  : a normal install -- ComfyUI + Custom-Scripts + one ordinary third-party
          node pack (Victim-Demo-Pack stands in for whatever the victim installed)
          and one ordinary workflow that uses the LoRA the victim downloaded.
          The workflow is built here, not by the attacker, and carries no payload.

Refuses to run if the environment is not in a clean pre-attack state.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

VICTIM_PACK = "Victim-Demo-Pack"

VICTIM_ORIGINAL = '''"""Victim-Demo-Pack -- an ordinary small ComfyUI node pack.

Stand-in for any node pack the victim has installed. It does nothing interesting;
it exists so the chain has a real package initializer to overwrite.
"""
import folder_paths


class ListLorasDemo:
    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {}}

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("loras",)
    FUNCTION = "run"
    CATEGORY = "victim-demo"

    def run(self):
        return (", ".join(folder_paths.get_filename_list("loras")),)


NODE_CLASS_MAPPINGS = {"ListLorasDemo": ListLorasDemo}
NODE_DISPLAY_NAME_MAPPINGS = {"ListLorasDemo": "List Loras (demo)"}
'''


def sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def victim_workflow_png(model_name: str, dest: pathlib.Path) -> None:
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo
    graph = {
        "last_node_id": 1, "last_link_id": 0, "version": 0.4,
        "nodes": [{"id": 1, "type": "LoraLoaderModelOnly", "pos": [220, 180],
                   "size": [340, 100], "flags": {}, "order": 0, "mode": 0,
                   "inputs": [{"name": "model", "type": "MODEL", "link": None}],
                   "outputs": [{"name": "MODEL", "type": "MODEL", "links": None}],
                   "properties": {"Node Name for S&R": "LoraLoaderModelOnly"},
                   "widgets_values": [model_name, 1.0]}],
        "links": [], "groups": [], "config": {}, "extra": {},
    }
    img = Image.new("RGB", (8, 8), (30, 30, 30))
    meta = PngInfo()
    meta.add_text("workflow", json.dumps(graph, sort_keys=True, separators=(",", ":")))
    img.save(dest, pnginfo=meta, optimize=False, compress_level=6)


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent
    root = pathlib.Path.home() / "cve_repro_modelspec"
    run = pathlib.Path(os.environ.get("RUN_DIR", root / "run"))
    run.mkdir(parents=True, exist_ok=True)
    comfy = pathlib.Path(os.environ.get("COMFY_ROOT", root / "src/ComfyUI"))
    art = pathlib.Path(os.environ.get("ART_DIR", root / "artifacts"))

    print("comfy root :", comfy)
    print("run dir    :", run)

    # --- pins ---------------------------------------------------------------
    want = json.loads((here / "pins.json").read_text())
    for name, (path, sha) in want.items():
        got = subprocess.run(["git", "-C", str(comfy / path), "rev-parse", "HEAD"],
                             capture_output=True, text=True).stdout.strip()
        print(f"pin {name:12s} {got}  {'OK' if got == sha else 'MISMATCH'}")
        if got != sha:
            print("PIN MISMATCH -> refusing to run")
            return 2

    # --- artifact integrity -------------------------------------------------
    sums = {}
    for line in (art / "SHA256SUMS.txt").read_text().splitlines():
        h, n = line.split("  ", 1)
        sums[n] = h
    for name, h in sums.items():
        got = sha256(art / name)
        if got != h:
            print(f"ARTIFACT TAMPERED {name}: {got} != {h}")
            return 3

    # --- plant the carrier --------------------------------------------------
    loras = comfy / "models" / "loras"
    loras.mkdir(parents=True, exist_ok=True)
    for name in ("evil_cs.safetensors", "benign_cs.safetensors"):
        shutil.copy2(art / name, loras / name)
        print(f"planted {name} -> {loras / name}")

    # --- the victim's installed node pack -----------------------------------
    pack = comfy / "custom_nodes" / VICTIM_PACK
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "__init__.py").write_text(VICTIM_ORIGINAL, encoding="utf-8")
    (pack / "README.md").write_text(
        "# Victim-Demo-Pack\n\nA tiny ComfyUI node pack used as the overwrite target.\n",
        encoding="utf-8")
    before = sha256(pack / "__init__.py")
    (run / "victim_init.before.sha256").write_text(before + "\n")
    (run / "victim_init.before.py").write_text(VICTIM_ORIGINAL, encoding="utf-8")
    print(f"victim pack initializer sha256 (before) = {before}")

    # the staged file's own hash, so the verification step never has to guess it
    staged = (art / "staged_init.py").read_bytes()
    (run / "staged.sha256").write_text(hashlib.sha256(staged).hexdigest() + "\n")

    # --- the victim's own workflow ------------------------------------------
    victim_workflow_png("benign_cs.safetensors", run / "victim_workflow_negctl.png")
    victim_workflow_png("evil_cs.safetensors", run / "victim_workflow_attack.png")
    print("victim workflow PNGs built (no payload inside them)")

    # --- preconditions ------------------------------------------------------
    marker = pathlib.Path(os.environ.get("MARKER_PATH", run / "staged_marker.json"))
    if marker.exists():
        print(f"PRECONDITION FAILED: marker already exists: {marker}")
        return 4
    staged_hash = sums["staged_init.py"]
    if sha256(pack / "__init__.py") == staged_hash:
        print("PRECONDITION FAILED: victim initializer is already the staged one")
        return 4
    tempdir = comfy / "temp"
    for f in tempdir.glob("staged_init*.py") if tempdir.exists() else []:
        print(f"PRECONDITION FAILED: stale upload present: {f}")
        return 4

    print("preconditions OK: marker absent, victim initializer is the original, temp clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
