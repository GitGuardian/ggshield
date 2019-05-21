# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots[
    "test_scan 1"
] = """Usage: cli scan [OPTIONS] [PATHS]...

  Command to scan various content.

Options:
  --pre-commit     Scan staged files
  --ci             Scan diff in a CI env [GITLAB | TRAVIS | CIRCLE]
  -r, --recursive  Scan directory recursively
  -y, --yes        Confirm recursive scan
  -v, --verbose    Print the list of all files before recursive scan
  -h, --help       Show this message and exit.
"""
