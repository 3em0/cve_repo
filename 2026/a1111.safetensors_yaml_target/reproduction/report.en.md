# a1111.safetensors_yaml_target — end-to-end validation

**Product:** AUTOMATIC1111/stable-diffusion-webui, release **v1.10.1**, commit
`82a973c04367123ae98bd9abdf80d9eda9b910e2` (verified inside the container with
`git rev-parse HEAD`).
**Host:** `.37` · **Image:** `mbe2e/v/a1111.safetensors_yaml_target:r1` on
`mbe2e/prod:a1111-82a973c0` · **Run time network:** `--network none`.

## What the attacker gets to do

Exactly one thing: publish a model package that the victim unpacks into
`models/Stable-diffusion/`. The package is

```
mbe2e_pack/
    model.safetensors   696-byte valid safetensors, written by safetensors.torch.save_file
    model.yaml          the same-basename sidecar config
    hubconf.py          an ordinary file; nothing on the victim machine imports it directly
```

No Python of ours runs on the victim machine. Nothing is imported, stubbed, or
monkeypatched. The product's `safe.py` RestrictedUnpickler, torch's
`weights_only` default and the real safetensors parser are all live.

## What the victim does

Starts the WebUI and selects the checkpoint. The selection is driven through the
product's own public API — the same call any model manager makes:

```
GET  /sdapi/v1/sd-models
POST /sdapi/v1/options   {"sd_model_checkpoint": "<title>"}
```

## The delegation

| step | code | what the field is treated as |
|---|---|---|
| 1 | `modules/sd_models.py:332-347` | the checkpoint is read by the real safetensors parser |
| 2 | `modules/sd_models_config.py:117-136` | `<basename>.yaml` is preferred **because the pathname matches** — no other relation is authenticated |
| 3 | `modules/sd_models.py:809` | `OmegaConf.load()` — still ordinary data |
| 4 | `modules/sd_models.py:599-602` | `repair_config()` injects `model.params.use_ema=False` |
| 5 | `modules/sd_models.py:766-775` | `instantiate_from_config`: `constructor = get_obj_from_str(config["target"])`, then `constructor(**params)` |
| 6 | `modules/sd_models.py:778-783` | `get_obj_from_str`: `importlib.import_module()` + `getattr` — **the string is now a module name** |
| 7 | `torch/hub.py` `_load_local` → `_import_module` | `spec.loader.exec_module()` on the package's own `hubconf.py` — **top-level attacker code runs as the WebUI process** |

Steps 5–6 are the DATA→CONTROL crossing: a YAML string that the loader read as
configuration is used, with no re-validation, as the name of a module to import
and a callable to invoke.

## Why the published PoCs do not survive the real product

The public write-ups for this root (including this project's own
`submission/01_A1111_yaml_RCE/`) use

```yaml
model:
  target: subprocess.run
  params:
    args: ["touch", "/tmp/pwned_by_a1111_yaml"]
```

and verify it by calling `instantiate_from_config` directly. **On the real
product path that gadget fails.** `repair_config()` (`sd_models.py:599-602`) runs
between `OmegaConf.load` and `instantiate_from_config` and adds
`model.params.use_ema = False`; `subprocess.run` forwards the unknown keyword to
`Popen`, which raises `TypeError`. Any gadget for this root must absorb
`**kwargs`. That is a concrete example of what code-slicing hides: the extracted
function body behaves differently from the same function inside the product.

The gadget used here, `torch.hub.load(..., source="local")`, does absorb
`**kwargs` and forwards them to the entry point. It is A1111's own pinned
`torch==2.1.2`, it needs no network, and `repo_or_dir` is a path **relative to
the WebUI's working directory**, which `webui.sh` always sets to the checkout
root — so the attacker does not have to guess an absolute install path.

## Negative control

`mbe2e_neg/` is byte-identical to `mbe2e_pack/` except for one string:
`model.target: torch.nn.Identity`. The same `hubconf.py` payload file sits in the
directory. It is selected **first**. Expected: the product log shows
`Creating model from config: models/Stable-diffusion/mbe2e_neg/model.yaml`
(the sidecar really was read) and no canary file appears.

## Result

See `exp/result.json` (byte-identical across two independent container runs) and
`exp/SHA256SUMS`.

## Verification boundary — what is NOT proven

- **Delivery is assumed.** The victim has to obtain and unpack the package. A1111
  core has no endpoint that downloads an arbitrary checkpoint bundle, so this is
  not unauthenticated network RCE against a stock instance.
- **The package is three files, not one.** `hubconf.py` is the payload carrier.
  The contract allows a model *directory* as the starting point, and shipping a
  `.py` beside weights is normal for Hugging Face repos, but a single-file
  version of this root would need a different `**kwargs`-absorbing gadget.
- `--skip-load-model-at-start` is used so the only checkpoint load in the run is
  the one the victim's API call causes. Without it the same thing happens at
  startup; the flag only removes ambiguity about *when*.
- The canary is a file write. No persistence, no network, no credential access.
- **Upstream availability:** `Stability-AI/stablediffusion`, which A1111 v1.10.1
  clones for the `ldm` package, returns HTTP 404 as of 2026-09-20, so a clean
  `launch.py` bootstrap of this release is impossible today. The pinned revision
  was recovered from Software Heritage and vendored. This does not affect the
  taint path but it does mean the image is not reproducible from upstream alone.
