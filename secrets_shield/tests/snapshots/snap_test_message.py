# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots[
    "TestMessage::test_message_multiple_secrets_one_line 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m2\x1b[0m secrets have been found in file \x1b[93m\x1b[1mleak.txt\x1b[0m
\x1b[37m\x1b[22m+FacebookAppId = \x1b[0m\x1b[91m\x1b[22m294790898041575\x1b[0m\x1b[37m\x1b[22m; FacebookAppSecret = \x1b[0m\x1b[91m\x1b[22mce3f9f0362bbe5ab01dfc8ee565e4372\x1b[0m\x1b[37m\x1b[22m;\x1b[0m
\x1b[97m\x1b[1m                 |_Facebook Access Tokens_|           |____Facebook Access Tokens____|\x1b[0m
\x1b[37m\x1b[22m
\x1b[0m"""

snapshots[
    "TestMessage::test_message_multiple_secrets_one_line_overlay 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m2\x1b[0m secrets have been found in file \x1b[93m\x1b[1mleak.txt\x1b[0m
\x1b[37m\x1b[22m+Facebook = \x1b[0m\x1b[91m\x1b[22m294790898041575\x1b[0m\x1b[37m\x1b[22m | \x1b[0m\x1b[91m\x1b[22mce3f9f0362bbe5ab01dfc8ee565e4372\x1b[0m\x1b[37m\x1b[22m;\x1b[0m
\x1b[97m\x1b[1m            |_Facebook Access Tokens_|
                              |____Facebook Access Tokens____|\x1b[0m
\x1b[37m\x1b[22m
\x1b[0m"""

snapshots[
    "TestMessage::test_message_multiple_secrets_two_lines 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m2\x1b[0m secrets have been found in file \x1b[93m\x1b[1mleak.txt\x1b[0m
\x1b[37m\x1b[22m+FacebookAppId = \x1b[0m\x1b[91m\x1b[22m294790898041575\x1b[0m\x1b[37m\x1b[22m;\x1b[0m
\x1b[97m\x1b[1m                 |_Facebook Access Tokens_|\x1b[0m
\x1b[37m\x1b[22m
+FacebookAppSecret = \x1b[0m\x1b[91m\x1b[22mce3f9f0362bbe5ab01dfc8ee565e4372\x1b[0m\x1b[37m\x1b[22m;\x1b[0m
\x1b[97m\x1b[1m                     |____Facebook Access Tokens____|\x1b[0m
\x1b[37m\x1b[22m
\x1b[0m"""

snapshots[
    "TestMessage::test_message_no_secret 1"
] = "\x1b[37m\x1b[22mNo secrets have been found\x1b[0m"

snapshots[
    "TestMessage::test_message_simple_secret 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m1\x1b[0m secret has been found in file \x1b[93m\x1b[1mleak.txt\x1b[0m
\x1b[37m\x1b[22m+github_token: \x1b[0m\x1b[91m\x1b[22m368ac3edf9e850d1c0ff9d6c526496f8237ddf91\x1b[0m\x1b[37m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m               |_____________GitHub Token_____________|\x1b[0m
\x1b[37m\x1b[22m
\x1b[0m"""
