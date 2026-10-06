"""Generate the model packages for the Show-o llm_model_path repo-redirect PoC.

Two first-hop Show-o model packages are produced with save_pretrained() from the
same in-memory model and therefore differ ONLY in the llm_model_path string of
their config.json:

  pkg_attacker/config.json  llm_model_path = "mbe2e-attacker/pwned-by-showo-llm-model-path-redirect"
  pkg_default/config.json   llm_model_path = "microsoft/phi-1_5"      (official value,
                             identical to configs/showo_demo_w_clip_vit.yaml:21)

Second-hop "hub" repositories served by mock_hub.py on 127.0.0.1 carry a data
config.json each - no .py, no plugins, no native libraries:
  hub/mbe2e-attacker/pwned-by-showo-llm-model-path-redirect/config.json
  hub/microsoft/phi-1_5/config.json                     (same baseline fields)

All models use a tiny Phi config (hidden_size 64, 2 layers) so the run is CPU
and memory friendly; the values are identical on both hops, so any difference in
behavior comes from the redirected repository identity alone.
"""
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
PINNED = os.path.join(HERE, "Show-o-45a5a2de01d1")
sys.path.insert(0, PINNED)

ATTACKER_REPO = "mbe2e-attacker/pwned-by-showo-llm-model-path-redirect"
OFFICIAL_REPO = "microsoft/phi-1_5"

PHI_CONFIG = {
    "model_type": "phi",
    "architectures": ["PhiForCausalLM"],
    "hidden_size": 64,
    "num_hidden_layers": 2,
    "num_attention_heads": 4,
    "intermediate_size": 128,
    "vocab_size": 1024,
    "max_position_embeddings": 512,
    "partial_rotary_factor": 0.4,
    "torch_dtype": "float32",
}

SHOWO_KWARGS = dict(
    w_clip_vit=False,
    vocab_size=1024,
    llm_vocab_size=1024,
    codebook_size=512,
    num_vq_tokens=64,
)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def main():
    from models.modeling_showo import Showo
    from transformers import AutoConfig

    print("generating PoC packages under %s" % WORK)
    # stale HF caches would satisfy AutoConfig.from_pretrained offline and hide the
    # redirected request from the mock-hub log - keep every run deterministic
    import glob
    for cache in glob.glob(os.path.join(WORK, "hf-home-*")):
        shutil.rmtree(cache)
        print("  cleared stale cache %s" % os.path.relpath(cache, WORK))
    seed_dir = os.path.join(WORK, "_seed_llm")
    os.makedirs(seed_dir, exist_ok=True)
    with open(os.path.join(seed_dir, "config.json"), "w", newline="\n") as f:
        json.dump(PHI_CONFIG, f, indent=2)
        f.write("\n")

    # build the Show-o model once; the frozen branch resolves the seed dir locally
    model = Showo(llm_model_path=seed_dir, load_from_showo=True, **SHOWO_KWARGS)

    sums = []
    for pkg_name, llm_path in (("pkg_attacker", ATTACKER_REPO), ("pkg_default", OFFICIAL_REPO)):
        pkg = os.path.join(WORK, pkg_name)
        if os.path.exists(pkg):
            shutil.rmtree(pkg)
        model.save_pretrained(pkg)
        cfg_file = os.path.join(pkg, "config.json")
        with open(cfg_file) as f:
            cfg = json.load(f)
        cfg["llm_model_path"] = llm_path
        with open(cfg_file, "w", newline="\n") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        for fname in sorted(os.listdir(pkg)):
            rel = os.path.relpath(os.path.join(pkg, fname), WORK)
            sums.append((rel, sha256(os.path.join(pkg, fname))))
        print("  %s -> llm_model_path = %s" % (pkg_name, llm_path))

    for repo, cfg in ((ATTACKER_REPO, PHI_CONFIG), (OFFICIAL_REPO, PHI_CONFIG)):
        rdir = os.path.join(WORK, "hub", *repo.split("/"))
        os.makedirs(rdir, exist_ok=True)
        cpath = os.path.join(rdir, "config.json")
        with open(cpath, "w", newline="\n") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        sums.append((os.path.relpath(cpath, WORK), sha256(cpath)))
    print("  hub repos written: %s | %s" % (ATTACKER_REPO, OFFICIAL_REPO))

    with open(os.path.join(WORK, "SHA256SUMS.txt"), "w", newline="\n") as f:
        for rel, digest in sums:
            f.write("%s  %s\n" % (digest, rel))
    print("SHA256SUMS.txt written with %d entries" % len(sums))


if __name__ == "__main__":
    main()
