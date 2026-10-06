# -*- coding: utf-8 -*-
"""Print class_from_module_path() from the pinned source with line numbers,
so the vulnerable code is visible in the terminal next to the PoC output."""
import io

PATH = "src/rasa_nlu/utils/__init__.py"
START, END = 163, 176

print(">>> %s  (pinned at commit f995c06e5aee)" % PATH)
with io.open(PATH, encoding="utf-8") as f:
    lines = f.read().splitlines()

for n in range(START, END + 1):
    print("%4d  %s" % (n, lines[n - 1]))
