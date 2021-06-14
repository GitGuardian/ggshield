# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots[
    "test_handle_scan_error[single file exception] 1"
] = """
Error scanning. Results may be incomplete.
Add the following files to your paths-ignore:
- /home/user/too/long/file/name: filename:: [ErrorDetail(string='Ensure this field has no more than 256 characters.', code='max_length')]
"""

snapshots[
    "test_handle_scan_error[too many documents] 1"
] = """
Error scanning. Results may be incomplete.
The following chunk is affected:
/example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example, /example
400:Too many documents to scan
"""
