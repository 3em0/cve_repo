# Reproduction kit — SakanaAI/evolutionary-model-merge @ 09aff543

Chain under test:

```
model package A (config.json only, no python, no auto_map)
  -> evomerge/modules/heron/video_blip/configuration_video_blip.py:385
       model_path = text_config["_name_or_path"]        # attacker-recorded
  -> configuration_video_blip.py:387-389
       AutoConfig.from_pretrained(model_path, trust_remote_code=True)
  -> repository B named by that field is fetched/imported and its module body runs
  -> modeling_video_blip.py:1960-1961 resolves B's auto_map["AutoModelForCausalLM"] as well
```

Quick start (from the report folder):

```powershell
docker build -t sakana-nested-name-or-path .\poc
docker run --rm -it -v "$PWD\poc:/work" sakana-nested-name-or-path bash
sh reproduce.sh
```

Layout:

| Path | Role |
|---|---|
| `Dockerfile` | `python:3.11-slim` + the versions pinned in the repo's `poetry.lock` (torch 2.1.2+cpu, transformers 4.38.2, …) |
| `evolutionary-model-merge-09aff543/` | pinned source snapshot (codeload tarball, commit `09aff543dd2ae966b3dfe457b750563ab063eb03`; `.github/` omitted) |
| `pinned_import.py` | imports the pinned `video_blip` modules without `evomerge/__init__.py` (that one pulls in a GPU-only vLLM fork) |
| `make_poc.py` | builds `work/attacker/model-A-evil`, `work/control/model-A-control`, `work/hub/model-A-hub`, `work/attacker/model-B-evil`, `work/benign/model-B-plain` |
| `payload/` | the two files repository B carries (they only write a marker file) |
| `victim_load.py` | the victim's normal operation: `VideoBlipForConditionalGeneration.from_pretrained(<package>, ignore_mismatched_sizes=True)` |
| `victim_config_only.py` | the same call stopped after the nested config is built (used for the 7B Hub reference) |
| `check_marker.py`, `env_versions.py` | evidence helpers |
| `reproduce.sh` | runs the whole sequence in one command |
| `shot_scenario.json`, `real_terminal_shot.ps1` | real-terminal screenshot driver and its scenario (see `../截图与复现指引.md`) |
| `SHA256SUMS.txt` | hashes of the generated samples (container-relative paths) |

`work/` is generated and is not shipped; `make_poc.py` rebuilds it (including the
`HF_MODULES_CACHE` under `work/hf-cache`, which must be fresh or a cached copy of B's
module shadows the payload).
