#!/usr/bin/env python3
"""Deterministic digest of a source tree. Identical code is used on the host
(before the build) and inside the container (self-verification at run time)."""
import hashlib, pathlib, sys

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
SKIP_SUFFIX = (".pyc", ".pyo")

def tree_sha256(root: str) -> str:
    root = pathlib.Path(root)
    h = hashlib.sha256()
    files = []
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        parts = rel.parts
        if any(x in SKIP_DIRS or x.endswith(".egg-info") or x.endswith(".dist-info")
               for x in parts):
            continue
        if not p.is_file() or p.is_symlink():
            continue
        if p.name.endswith(SKIP_SUFFIX):
            continue
        files.append((rel.as_posix(), p))
    for rel, p in sorted(files):
        h.update(rel.encode() + b"\0" +
                 hashlib.sha256(p.read_bytes()).hexdigest().encode() + b"\n")
    return h.hexdigest()

if __name__ == "__main__":
    print(tree_sha256(sys.argv[1]))
