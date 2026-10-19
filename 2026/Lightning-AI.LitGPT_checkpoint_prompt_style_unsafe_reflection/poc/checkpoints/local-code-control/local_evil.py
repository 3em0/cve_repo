# local_evil.py is deliberately shipped INSIDE the checkpoint directory.
# If LitGPT imported model-directory files, Evil() below would drop a marker
# file next to this script when instantiated. The PoC shows it never runs.
class Evil:
    def __init__(self):
        from pathlib import Path

        Path(__file__).with_name("LOCAL_EVIL_RAN").write_text("imported")
