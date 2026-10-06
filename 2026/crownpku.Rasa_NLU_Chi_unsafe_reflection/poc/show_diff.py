# -*- coding: utf-8 -*-
"""Show that the positive and negative model directories differ ONLY in
pipeline[0].class (the string that reaches class_from_module_path)."""
import io
import json

pos = json.load(io.open("model_pos/metadata.json", encoding="utf-8"))
neg = json.load(io.open("model_neg/metadata.json", encoding="utf-8"))

print("model_pos pipeline[0].class:", pos["pipeline"][0]["class"])
print("model_neg pipeline[0].class:", neg["pipeline"][0]["class"])

pos["pipeline"][0].pop("class")
neg["pipeline"][0].pop("class")
print("everything else identical:", pos == neg)
