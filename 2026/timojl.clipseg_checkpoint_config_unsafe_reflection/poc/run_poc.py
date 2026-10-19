#!/usr/bin/env python3
"""Drive the *pinned, unmodified* CLIPSeg loader against one carrier arm.

The loader under test is `general_utils.load_model()` of the pinned checkout
(commit 77c4e2dc853880df46413d4a870a725e961f2f73). Nothing in the product is patched:
the file is imported straight from `poc/source/clipseg-77c4e2d` and the process is run
with the arm workspace as its working directory, because the loader resolves
`logs/<checkpoint_id>/config.json` and `logs/<checkpoint_id>/weights.pth` relative to CWD.

Exit code is the verdict: 0 = the arm behaved as the report claims, 1 = it did not.

Usage:  python run_poc.py --arm positive
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, 'source', 'clipseg-77c4e2d')
CKPT_ID = 'rd64-uni'
MARKER = os.path.join('out', 'clipseg_reflective_sink_marker')
IMPACT_TARGET = os.path.join('out', 'clipseg_impact_target')

# what each arm must show for the report's claim to hold
EXPECT = {
    'positive':       {'marker': True,  'target_truncated': None},
    'negative':       {'marker': False, 'target_truncated': None},
    'impact':         {'marker': None,  'target_truncated': True},
    'before-weights': {'marker': True,  'target_truncated': None},
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--arm', required=True, choices=sorted(EXPECT))
    ap.add_argument('--root', default=os.path.join(tempfile.gettempdir(), 'poc-work', 'clipseg-77c4e2d'))
    args = ap.parse_args()

    work = os.path.join(os.path.abspath(args.root), args.arm)
    ckpt_dir = os.path.join(work, 'logs', CKPT_ID)
    cfg_path = os.path.join(ckpt_dir, 'config.json')
    weights_path = os.path.join(ckpt_dir, 'weights.pth')
    if not os.path.isfile(cfg_path):
        sys.exit(f'arm not built: {cfg_path} (run make_poc.py first)')

    cfg = json.load(open(cfg_path, encoding='utf-8'))
    weights_before = os.path.getsize(weights_path)

    os.chdir(work)                      # the loader works relative to the victim's CWD
    sys.path.insert(0, SOURCE)
    from general_utils import load_model, get_attribute   # pinned source, unmodified

    result = {
        'arm': args.arm,
        'pinned_source': SOURCE,
        'cwd': os.getcwd(),
        'checkpoint_id': CKPT_ID,
        'config_json': cfg,
        'config_sha256': sha256(cfg_path),
        'weights_sha256': sha256(weights_path),
        'resolved_class': repr(get_attribute(cfg['model'])),
        'load_model_exception': None,
        'marker_exists': None,
        'impact_target_bytes': None,
        'verdict': None,
    }

    try:
        model = load_model(CKPT_ID)
        result['load_model_returned'] = repr(model)
    except BaseException as exc:                      # the product's own crash is evidence too
        result['load_model_exception'] = f'{type(exc).__name__}: {exc}'
        result['traceback_tail'] = traceback.format_exc().strip().splitlines()[-4:]

    marker_path = os.path.join(work, MARKER)
    result['marker_exists'] = os.path.isfile(marker_path)
    if os.path.isfile(marker_path):
        result['marker_path'] = marker_path
        result['marker_bytes'] = os.path.getsize(marker_path)

    target_path = os.path.join(work, IMPACT_TARGET)
    if os.path.isfile(target_path):
        result['impact_target_bytes'] = os.path.getsize(target_path)
        result['impact_target_path'] = target_path

    exp = EXPECT[args.arm]
    ok = True
    if exp['marker'] is not None and result['marker_exists'] != exp['marker']:
        ok = False
    if exp['target_truncated'] is not None:
        truncated = result['impact_target_bytes'] == 0
        if truncated != exp['target_truncated']:
            ok = False
    result['verdict'] = 'PASS' if ok else 'FAIL'

    print(json.dumps(result, indent=2))
    print()
    print(f'[{args.arm}] marker_exists={result["marker_exists"]} '
          f'impact_target_bytes={result["impact_target_bytes"]} '
          f'weights.pth {weights_before} bytes '
          f'-> verdict {result["verdict"]}')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
