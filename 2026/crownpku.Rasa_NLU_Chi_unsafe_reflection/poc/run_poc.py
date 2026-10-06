# -*- coding: utf-8 -*-
"""Victim: load a model directory handed to us by someone else, then parse
one text. This is the normal rasa_nlu usage pattern:
Interpreter.load(MODEL).parse(TEXT)."""
import json
import sys

from rasa_nlu.model import Interpreter

model_dir = sys.argv[1]
text = u"meeting next wednesday at 3pm"

print("[victim] loading model directory:", model_dir)
interpreter = Interpreter.load(model_dir)
print("[victim] model loaded OK, calling parse() ...")
result = interpreter.parse(text)
print("[victim] parse() returned:")
print(json.dumps(result, ensure_ascii=False, indent=2))
