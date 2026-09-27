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

Not included (environment, not evidence — rebuild them per `../截图与复现指引.md` §5):

- `ComfyUI-387f98aa/` — pristine reference copy of ComfyUI at `387f98aa2822f684b8597959a52a467d88cc4806`
- `ComfyUI-Easy-Use-450b1ce4/` — pristine reference copy of ComfyUI-Easy-Use at
  `450b1ce4ce43b2280521c87f5fa388a898fb2ad2`
- `live/ComfyUI/` — the Windows-side pristine runtime tree

Both pinned trees are ordinary `git clone` + `git checkout <sha>` of the upstream
repositories; nothing in them was modified. `截图与复现指引.md` §5 reproduces the exact
commands (venv, requirements, runtime tree at `/srv/poc-work/ComfyUI`).
