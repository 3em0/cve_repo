"""Import-only stub of the `xformers` package for the CPU-only reproduction box.

eva_vit.py does an unguarded `import xformers.ops as xops` at module level.
The audio-encoder code path under test never calls any xformers op, so this
stub only has to make the import succeed; calling the stubbed function raises.
The pinned VITA source itself is not modified.
"""
