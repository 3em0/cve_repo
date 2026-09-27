# poc/ — what is included and what is not

Included here:

- `make_poc.py`, `drive.py`, `verify.py` — carrier builder, browser driver, post-restart verifier
- `real_terminal_shot.ps1` + `shot_scenario_1..4.json` — the real-terminal capture scenarios
  (build -> server -> drive -> restore); run them in this order to reproduce the screenshots
- `live_config.json` — paths used by the driver (`root` = the WSL runtime tree, `base` = the
  server address); edit `root` for your own machine
- `artifacts/` — the carrier and control files, with their SHA-256 in `SHA256SUMS.txt`
- `live/evidence/` — the dynamic case file of the published run: `phase_neg.json`,
  `phase_pos.json`, `result.json` and the four browser captures

Not included (environment, not evidence). Both pinned trees are ordinary
`git clone` + `git checkout <sha>` of the upstream repositories; nothing in them was modified.
Rebuild the runtime stack like this (WSL2, any distro):

    python3 -m venv ~/.venvs/easyuse
    ~/.venvs/easyuse/bin/pip install torch torchvision torchaudio \
        --index-url https://download.pytorch.org/whl/cpu
    # ComfyUI @ 387f98aa2822f684b8597959a52a467d88cc4806
    ~/.venvs/easyuse/bin/pip install -r <ComfyUI tree>/requirements.txt
    # ComfyUI-Easy-Use @ 450b1ce4ce43b2280521c87f5fa388a898fb2ad2
    ~/.venvs/easyuse/bin/pip install -r <Easy-Use tree>/requirements.txt
    sudo mkdir -p /srv/poc-work && sudo chown $USER /srv/poc-work
    # then copy a pristine ComfyUI tree to /srv/poc-work/ComfyUI and install
    # ComfyUI-Easy-Use @ 450b1ce4 into its custom_nodes/

Omitted copies:

- `ComfyUI-387f98aa/` — pristine ComfyUI at `387f98aa2822f684b8597959a52a467d88cc4806`
- `ComfyUI-Easy-Use-450b1ce4/` — pristine ComfyUI-Easy-Use at `450b1ce4ce43b2280521c87f5fa388a898fb2ad2`
- `live/ComfyUI/` — the Windows-side pristine runtime tree
