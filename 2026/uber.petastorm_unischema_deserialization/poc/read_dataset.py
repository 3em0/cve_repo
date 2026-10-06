#!/usr/bin/env python3
"""Victim-side consumer: read a petastorm dataset through the public API.

This is what a training job does after downloading a model package -- it never
touches the metadata footer itself, it just calls ``petastorm.make_reader``.

Run:  python read_dataset.py <dataset-dir>
"""

import os
import sys

from petastorm import make_reader


def dataset_url(dataset):
    """petastorm needs a URL; a plain local path is turned into a file:// URL."""
    if '://' in dataset:
        return dataset
    return 'file://' + os.path.abspath(dataset)


def main():
    if len(sys.argv) != 2:
        print('usage: python read_dataset.py <dataset-dir>')
        return 2

    dataset = sys.argv[1]
    print('opening petastorm dataset: {}'.format(dataset_url(dataset)))
    try:
        with make_reader(dataset_url(dataset)) as reader:
            for index, row in enumerate(reader):
                print('row {}: {}'.format(index, row))
    except Exception as exc:  # noqa: BLE001 - report whatever the reader raised
        print('reader raised {}: {}'.format(type(exc).__name__, exc))
    return 0


if __name__ == '__main__':
    sys.exit(main())
