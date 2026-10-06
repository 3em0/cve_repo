# Load a .pth checkpoint exactly the way spann3r does (vulnerable code under test):
#
#   HengyiWang/spann3r @ f89d6a23a842, dust3r/model.py, load_model():
#     :33  ckpt = torch.hub.load_state_dict_from_url(...)   (URL branch)
#     :35  ckpt = torch.load(model_path_or_url, map_location='cpu')   (file branch, bare load)
#     :36  args = ckpt['args'].model.replace("ManyAR_PatchEmbed", "PatchEmbedDust3R")
#     :47  net = eval(args)
#
# Usage: python run_load.py <checkpoint.pth>
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "spann3r-f89d6a23"))

from dust3r.model import load_model  # noqa: E402

if len(sys.argv) != 2:
    print("usage: python run_load.py <checkpoint.pth>")
    sys.exit(2)

ckpt = sys.argv[1]
print(f"[run_load] loading {ckpt} via spann3r dust3r.model.load_model")
net = load_model(ckpt)
print(f"[run_load] LOAD COMPLETED -> {type(net).__name__}")
