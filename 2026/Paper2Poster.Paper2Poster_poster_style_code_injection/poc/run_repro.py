#!/usr/bin/env python3
"""Replay Paper2Poster's real style-config -> generated-code -> exec path.

Pinned revision: Paper2Poster/Paper2Poster @ 623d042 (2026-06-08).

The driver calls the *unmodified* product functions, in the order
`PosterAgent/new_pipeline.py` calls them:

    new_pipeline.py:59   os.makedirs(args.tmp_dir, exist_ok=True)
    new_pipeline.py:304  yaml_cfg = load_poster_yaml_config(args.poster_path)
    new_pipeline.py:309  section_title_vertical_align = extract_vertical_alignment(yaml_cfg)
    new_pipeline.py:380  theme = create_theme_with_alignment(get_default_theme(), ...)
    new_pipeline.py:385  poster_code = generate_poster_code(...)
    new_pipeline.py:412  output, err = run_code(poster_code)

Only the LLM/VLM stages that run *before* line 302 (paper parsing, layout search,
poster-copy generation) are skipped: they need paid model credentials and none of
them touches the style value.  Everything from the YAML read to the exec() is the
product's own code.

--launch-from selects the process working directory, which decides whether the
per-poster file is the last writer of the merged config:

    run-dir    working directory without config/poster.yaml  -> poster.yaml wins
    repo-root  the checkout root (documented usage)          -> config/poster.yaml
               overwrites section_title_vertical_align first
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import types

SKIPPED_INITS: list[str] = []


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def register_package(name: str, path: pathlib.Path, skipped_init: str) -> None:
    """Make `name` importable without executing its (re-export only) __init__.py.

    `utils/__init__.py` and `utils/src/__init__.py` contain nothing but
    `from . import <submodules>` lines; the submodules they pull in eagerly are
    the *evaluation* stack (poster_eval_utils -> marker-pdf / docling / OCR),
    which the poster-generation path never uses. Registering the package
    namespace keeps every module that this driver imports byte-identical to the
    pinned revision - no product file is modified and no function is reimplemented.
    """
    module = types.ModuleType(name)
    module.__path__ = [str(path)]
    module.__package__ = name
    sys.modules[name] = module
    SKIPPED_INITS.append(skipped_init)


TEXTBOX = {"textbox_name": "section_title_1", "x": 1.0, "y": 1.0, "width": 20.0, "height": 3.0}
TITLE_SPEC = [
    {
        "bullet": False,
        "level": 0,
        "alignment": "left",
        "font_size": 80,
        "runs": [{"text": "1  Introduction", "bold": True, "italic": False,
                  "color": [0, 0, 0], "fill_color": None}],
    }
]
BODY_SPEC = [
    {
        "bullet": True,
        "level": 0,
        "alignment": "left",
        "font_size": 60,
        "runs": [{"text": "Poster body placeholder.", "bold": False, "italic": False,
                  "color": [47, 85, 151], "fill_color": None}],
    }
]
CONTENT = [{"title": TITLE_SPEC, "textbox1": BODY_SPEC}]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, help="directory holding paper.pdf + poster.yaml")
    ap.add_argument("--src", default=os.path.expanduser("~/p2p-repro/Paper2Poster-623d042"),
                    help="pinned checkout to import the product from")
    ap.add_argument("--marker", required=True, help="file the injected command is expected to create")
    ap.add_argument("--launch-from", choices=["run-dir", "repo-root"], default="run-dir")
    ap.add_argument("--run-dir", default=None, help="scratch cwd for launch-from=run-dir")
    ap.add_argument("--dump-code", default=None, help="write the generated Python program here")
    args = ap.parse_args()

    src = pathlib.Path(args.src).expanduser().resolve()
    workspace = pathlib.Path(args.workspace).expanduser().resolve()
    poster_path = workspace / "paper.pdf"
    marker = pathlib.Path(args.marker).expanduser().resolve()
    run_dir = pathlib.Path(args.run_dir).expanduser().resolve() if args.run_dir else workspace.parent / "run-cwd"
    run_dir.mkdir(parents=True, exist_ok=True)
    # relative --dump-code paths belong to the caller, not to the directory the product chdir()s into
    invocation_cwd = pathlib.Path.cwd()

    # fresh state: the marker must not exist before the trigger
    marker.unlink(missing_ok=True)

    print(f"[env]    pinned source : {src}")
    revision = ""
    try:
        revision = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        pass
    if not revision:
        rev_file = src / "REVISION"
        revision = rev_file.read_text().strip() if rev_file.exists() else "n/a"
    print(f"[env]    revision      : {revision}")
    print(f"[carrier] paper.pdf    : {poster_path}  sha256={sha256(poster_path)[:16]}...")
    print(f"[carrier] poster.yaml  : {workspace / 'poster.yaml'}  sha256={sha256(workspace / 'poster.yaml')[:16]}...")
    print(f"[state]  marker before : exists={marker.exists()}  ({marker})")

    cwd = src if args.launch_from == "repo-root" else run_dir
    os.chdir(cwd)
    print(f"[env]    process cwd   : {cwd}   (--launch-from {args.launch_from})")

    sys.path.insert(0, str(src))
    register_package("utils", src / "utils", "utils/__init__.py")
    register_package("utils.src", src / "utils" / "src", "utils/src/__init__.py")
    register_package("PosterAgent", src / "PosterAgent", "PosterAgent/__init__.py")
    print(f"[env]    loader note   : skipped the three re-export-only __init__.py files "
          f"({'; '.join(SKIPPED_INITS)}); every module used below is pinned code")

    from utils.config_utils import load_poster_yaml_config, extract_vertical_alignment
    from utils.theme_utils import get_default_theme, create_theme_with_alignment
    from PosterAgent.gen_pptx_code import generate_poster_code
    from utils.wei_utils import run_code, utils_functions

    os.makedirs("tmp", exist_ok=True)                    # new_pipeline.py:59

    yaml_cfg = load_poster_yaml_config(str(poster_path))  # new_pipeline.py:304
    print(f"[step1]  load_poster_yaml_config() -> {json.dumps(yaml_cfg, ensure_ascii=False)}")

    vertical_align = extract_vertical_alignment(yaml_cfg)  # new_pipeline.py:309
    print(f"[step2]  extract_vertical_alignment() -> {vertical_align!r}")

    theme = create_theme_with_alignment(get_default_theme(), vertical_align)  # new_pipeline.py:380
    print(f"[step3]  theme['section_title_vertical_align'] -> {theme.get('section_title_vertical_align')!r}")

    poster_code = generate_poster_code(                  # new_pipeline.py:385
        panel_arrangement_list=[],
        text_arrangement_list=[TEXTBOX],
        figure_arrangement_list=[],
        presentation_object_name="poster_presentation",
        slide_object_name="poster_slide",
        utils_functions=utils_functions,
        slide_width=48,
        slide_height=36,
        img_path=None,
        save_path="tmp/poster.pptx",
        visible=False,
        content=CONTENT,
        theme=theme,
        tmp_dir="tmp",
    )
    injected = [ln for ln in poster_code.splitlines() if ln.strip().startswith("fill_textframe(")]
    if args.dump_code:
        dump = pathlib.Path(args.dump_code)
        if not dump.is_absolute():
            dump = invocation_cwd / dump
        dump.parent.mkdir(parents=True, exist_ok=True)
        dump.write_text(poster_code, encoding="utf-8")
        print(f"[step4]  generated program written to {dump}")
    print("[step4]  generated program, interpolated style value:")
    for ln in injected:
        print(f"           {ln.strip()}")

    output, err = run_code(poster_code)                  # new_pipeline.py:412
    print(f"[step5]  run_code() -> error={err!r}")
    pptx = pathlib.Path("tmp/poster.pptx")
    print(f"[step5]  product output : {pptx} exists={pptx.exists()} size={pptx.stat().st_size if pptx.exists() else 0}")

    hit = marker.exists()
    print(f"[state]  marker after  : exists={hit}  ({marker})")
    if hit:
        print("[state]  marker content:")
        for line in marker.read_text().splitlines():
            print(f"           {line}")
        print("[verdict] injected command EXECUTED by the product's own exec() path")
        return 0
    print("[verdict] injected command did NOT execute (marker absent)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
