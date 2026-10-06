# PoC kit — AHEKOT/ComfyUI_VNCCS stored XSS

Pinned source: `ComfyUI_VNCCS-2206d174/` = AHEKOT/ComfyUI_VNCCS at
`2206d1743f7920a7b9a21f80f03777d9ddce74c3` (2026-08-29, `pyproject.toml` version 3.1.2),
copied from a `git checkout` of that commit with `.git/` and the 23 MB `images/` removed.

The vulnerable sink was verified in that tree before anything else was built:

```
web/vnccs_character_generator.js:2576  renderSettings() {
web/vnccs_character_generator.js:2588      info.innerHTML = `
web/vnccs_character_generator.js:2592          ...${this.data.character_name || "Select in Emotion Studio"}...
```

Same unescaped sink on current main (`381cf10796d767de49dd2e3981f2d9c7ffbaaa19`, 3.2.2):
`web/vnccs_character_generator.js:3159`.

## Files

| File | Purpose |
|---|---|
| `make_poc.py` | Builds the five workflow artifacts in `../samples/` and `SHA256SUMS.txt`. Stdlib only. |
| `verify_poc.py` | Drives the real stack: real ComfyUI server + real Chromium (Playwright), opens the artifact through the frontend's own workflow-open input (`#comfy-file-input` → `app.loadGraphData`), then reports what `readData()` produced, what the sink injected, whether the image loaded and whether the inline handler ran. |
| `shot_scenario_1_build.json` | Terminal capture scenario: build the artifacts. |
| `shot_scenario_2_server.json` | Terminal capture scenario: start the pinned ComfyUI stack. |
| `shot_scenario_3_drive.json` | Terminal capture scenario: five verification runs. |
| `shot_scenario_3b_positive.json` | Terminal capture scenario for the positive sample plus the extra `--browser-shot` run that produced `screenshots/10-browser-positive.png`. |
| `real_terminal_shot.ps1` | Capture driver copied from the `cve-report` skill (opens a fresh terminal per run, UTF-8 with BOM). |
| `shoot_window_reuse.ps1` | Capture driver variant: attaches to an already-open terminal window and minimises it while a command runs, so a second automation agent on the same desktop cannot paste into it. Same real window, same real commands. |
| `SHA256SUMS.txt` | Digests of the generated artifacts. |

## Expected results

| Sample | Expected | Meaning |
|---|---|---|
| `poc_xss_positive.json` | `fire` | Payload in `character_name`, `src` unloadable → `onerror` runs in the ComfyUI origin |
| `poc_xss_negative_control.json` | `nofire` | Same id, same handler, valid data-URI `src` → handler never fires |
| `poc_control_missing_field.json` | `nofire` | `widgets_values[0]` = `{}` → nothing reaches the sink |
| `control_two_node_topology.json` | `nofire` | `character_name` overwritten by an `EmotionGeneratorV2` node in the same workflow |
| `control_legacy_two_slot.json` | `nofire` | Frontend `migrateWidgetsValues()` discards slot 0 of the two-element layout |

No product code is patched or mocked: the only thing the kit does is hand a JSON file to the
product's own loading path.
