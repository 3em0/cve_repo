#!/usr/bin/env python3
"""Print the relevant excerpts of the *pinned* CLIPSeg source with real line numbers.

This is a read-only viewer: it never edits the checkout. Usage:

    python show_vuln_code.py reflect    # general_utils.py: the reflection + the sink
    python show_vuln_code.py callers    # score.py: the public CLI path that reaches it
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, 'source', 'clipseg-77c4e2d')

SECTIONS = {
    # (file, [(start, end), ...], header)
    'reflect': ('general_utils.py', [(180, 188), (201, 214)],
                'get_attribute() resolves an arbitrary dotted name; load_model() takes that\n'
                'name straight from the checkpoint config.json and constructs it'),
    'callers': ('score.py', [(24, 40), (140, 148)],
                'the documented `python score.py <experiment>.yaml <id> <test_id>` path:\n'
                'the same sink is duplicated here and reached from main() -> score()'),
}

NOTES = {
    ('reflect', 186): 'reflection: attacker-controlled string',
    ('reflect', 187): 'import_module() on the artifact module path',
    ('reflect', 188): 'getattr() resolves any attribute of it',
    ('reflect', 203): 'checkpoint config.json (attacker file)',
    ('reflect', 208): 'the model class comes from the artifact',
    ('reflect', 212): 'config keys matched to class signature',
    ('reflect', 214): 'SINK: artifact-selected callable constructed',
    ('callers', 26): 'same config.json',
    ('callers', 31): 'same reflection',
    ('callers', 37): 'same sink',
    ('callers', 147): 'public entry: documented CLI',
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in SECTIONS:
        sys.exit(f'usage: {os.path.basename(__file__)} {{{"|".join(SECTIONS)}}}')
    name = sys.argv[1]
    rel, ranges, header = SECTIONS[name]
    path = os.path.join(SOURCE, rel)
    lines = open(path, encoding='utf-8').read().splitlines()

    print(f'=== {rel}  (pinned commit 77c4e2d, {len(lines)} lines) ===')
    print(header)
    print()
    for start, end in ranges:
        if start > 1 and ranges[0][0] != start:
            print('        ...')
        for i in range(start, end + 1):
            note = NOTES.get((name, i))
            marker = f'   <-- {note}' if note else ''
            print(f'{i:4d}  {lines[i - 1]}{marker}')
        print()


if __name__ == '__main__':
    main()
