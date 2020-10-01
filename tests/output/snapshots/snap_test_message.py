# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots['test_message_no_secret 1'] = '''\x1b[37m\x1b[22m\x1b[22mNo secrets have been found
\x1b[0m'''
