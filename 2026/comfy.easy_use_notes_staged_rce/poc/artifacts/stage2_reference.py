# stage 2 sentinel: this file replaced custom_nodes/ComfyUI-Easy-Use/__init__.py, so ComfyUI
# imports it during custom-node import on startup. It writes an inert canary
# marker next to itself and exports empty node mappings.
import pathlib
p = pathlib.Path(__file__).resolve().parent / 'STAGE2_CANARY.txt'
p.write_text('MBE2E-CANARY-comfy-easyuse-notes-stage2' + chr(10), encoding='utf-8')
NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}
__all__ = ['NODE_CLASS_MAPPINGS', 'NODE_DISPLAY_NAME_MAPPINGS']
