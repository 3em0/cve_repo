#!/usr/bin/env python
"""Report whether the marker written by the payload module exists."""

import pathlib

MARKER = pathlib.Path("/tmp/sakana_nested_name_or_path_marker")

if MARKER.exists():
    print(f"[check] marker EXISTS: {MARKER}")
    print("[check] content:", MARKER.read_text().strip())
else:
    print(f"[check] marker absent: {MARKER}")
