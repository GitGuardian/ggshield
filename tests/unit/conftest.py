import json
import os
import platform
import warnings
from os.path import dirname, join, realpath
from pathlib import Path
from typing import Any, Dict, Union

import pytest
import vcr
import yaml
from click.testing import CliRunner, Result
from pyfakefs.fake_filesystem import FakeFilesystem
from pygitguardian import GGClient
from pygitguardian.models import ScanResult, SecretIncident
from requests.utils import DEFAULT_CA_BUNDLE_PATH, extract_zipped_paths

from ggshield.core.cache import Cache
from ggshield.core.ui.reset import reset
from ggshield.core.url_utils import dashboard_to_api_url
from ggshield.utils.git_shell import (
    _get_git_path,
    _git_rev_parse_absolute,
    read_git_file,
)
from tests.conftest import GG_VALID_TOKEN


def is_macos():
    return platform.system() == "Darwin"


DATA_PATH = Path(__file__).parent.absolute() / "data"


_MULTIPLE_SECRETS_PATCH_CONTENT = """@@ -0,0 +1,2 @@
+FacebookAppKeys :
+String docker run --name geonetwork -d \
            -p 8080:8080 -e MYSQL_HOST=google.com \
            -e MYSQL_PORT=5434 -e MYSQL_USERNAME=root \
            -e MYSQL_PASSWORD=m42ploz2wd geonetwork
"""

_MULTIPLE_SECRETS_PATCH = (
    """commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 A\0test.txt\0\0diff --git a/test.txt b/test.txt
new file mode 100644
index 0000000..b80e3df
--- /dev/null
+++ b/test.txt
"""
    + _MULTIPLE_SECRETS_PATCH_CONTENT
)

_MULTIPLE_SECRETS_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policy_break_count": 1,
        "policies": ["Secrets detection", "File extensions", "Filenames"],
        "policy_breaks": [
            {
                "type": "MySQL Assignment",
                "detector_name": "mysql_assignment",
                "detector_group_name": "mysql_credentials",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/mysql_credentials",
                "policy": "Secrets detection",
                "matches": [
                    {
                        "type": "host",
                        "match": "google.com",
                        "index_start": 114,
                        "index_end": 123,
                        "line_start": 3,
                        "line_end": 3,
                    },
                    {
                        "type": "port",
                        "match": "5434",
                        "index_start": 151,
                        "index_end": 154,
                        "line_start": 3,
                        "line_end": 3,
                    },
                    {
                        "type": "username",
                        "match": "root",
                        "index_start": 174,
                        "index_end": 177,
                        "line_start": 3,
                        "line_end": 3,
                    },
                    {
                        "type": "password",
                        "match": "m42ploz2wd",
                        "index_start": 209,
                        "index_end": 218,
                        "line_start": 3,
                        "line_end": 3,
                    },
                ],
            }
        ],
    }
)

API_TOKENS_RESPONSE_SCAN_SCOPES = {
    "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
    "name": "myTokenName",
    "workspace_id": 42,
    "type": "personal_access_token",
    "status": "revoked",
    "created_at": "2023-05-20T12:40:55.662949Z",
    "last_used_at": "2023-05-24T12:40:55.662949Z",
    "expire_at": None,
    "revoked_at": "2023-05-27T12:40:55.662949Z",
    "member_id": 22015,
    "creator_id": 22015,
    "scopes": ["scan"],
}

API_TOKENS_RESPONSE_SCAN_CREATE_INCIDENTS_SCOPES = {
    "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
    "name": "myTokenName",
    "workspace_id": 42,
    "type": "personal_access_token",
    "status": "active",
    "created_at": "2023-05-20T12:40:55.662949Z",
    "last_used_at": "2023-05-24T12:40:55.662949Z",
    "expire_at": None,
    "revoked_at": None,
    "member_id": 22015,
    "creator_id": 22015,
    "scopes": ["scan:create-incidents"],
}

# This long token is a test token, always reported as an uncheckable secret
GG_TEST_TOKEN = (
    "8a784aab7090f6a4ba3b9f7a6594e2e727007a26590b58ed314e4b9ed4536479sRZlRup3xvtMVfiHWA"
    "anbe712Jtc3nY8veZux5raL1bhpaxiv0rfyhFoAIMZUCh2Njyk7gRVsSQFPrEphSJnxa16SIdWKb03sRft"
    "770LUTTYTAy3IM18A7Su4HjiHlGA9ihLj9ou3luadfRAATlKH6kAZwTw289Kq9uip67zxyWkUJdh6PTeFp"
    "MgCh3AhHcZ21VeZHlu12345"
)

UNCHECKED_SECRET_PATCH = f"""commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 A\0test\0\0diff --git a/test b/test
new file mode 100644
index 0000000..b80e3df
--- /dev/null
+++ b/test
@@ -0,0 +2 @@
+# gg token
+apikey = "{GG_TEST_TOKEN}";
"""

VALID_SECRET_PATCH = f"""commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 A\0test\0\0diff --git a/test b/test
new file mode 100644
index 0000000..b80e3df
--- /dev/null
+++ b/test
@@ -0,0 +2 @@
+# gg token
+apikey = "{GG_VALID_TOKEN}";
"""

_SIMPLE_SECRET_TOKEN = "368ac3edf9e850d1c0ff9d6c526496f8237ddf91"  # ggignore
_SIMPLE_SECRET_PATCH = f"""@@ -0,0 +1 @@
+github_token: {_SIMPLE_SECRET_TOKEN}
"""
_SIMPLE_SECRET_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": "GitHub Token",
                "detector_name": "github_token",
                "detector_group_name": "github_access_token",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/github_access_token",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": _SIMPLE_SECRET_TOKEN,
                        "type": "apikey",
                        "index_start": 29,
                        "index_end": 69,
                    }
                ],
            }
        ],
        "policy_break_count": 1,
    }
)

_SIMPLE_SECRET_WITH_FILENAME_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["Secrets detection"],
        "policy_breaks": [
            {
                "type": "GitHub Token",
                "detector_name": "github_token",
                "detector_group_name": "github_access_token",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/github_access_token",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": _SIMPLE_SECRET_TOKEN,  # noqa
                        "type": "apikey",
                        "index_start": 29,
                        "index_end": 69,
                    }
                ],
            },
        ],
        "policy_break_count": 1,
    }
)

_MULTI_SECRET_ONE_LINE_PATCH = """@@ -0,0 +1 @@
+FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;

"""

_MULTI_SECRET_ONE_LINE_FULL_PATCH = (
    """commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 A\0test\0\0diff --git a/test b/test
new file mode 100644
index 0000000..3c9af3f
--- /dev/null
+++ b/test
"""
    + _MULTI_SECRET_ONE_LINE_PATCH
)

_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": "Facebook Access Token",
                "detector_name": "facebook_access_token",
                "detector_group_name": "facebook_access_token",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/facebook_access_token",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041575",
                        "index_start": 31,
                        "index_end": 45,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                        "index_start": 68,
                        "index_end": 99,
                        "type": "client_secret",
                    },
                ],
            }
        ],
        "policy_break_count": 1,
    }
)


_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY = """@@ -0,0 +1 @@
+Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;

"""

_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": "Facebook Access Token",
                "detector_name": "facebook_access_token",
                "detector_group_name": "facebook_access_token",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/facebook_access_token",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041575",
                        "index_start": 26,
                        "index_end": 40,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                        "index_start": 44,
                        "index_end": 75,
                        "type": "client_secret",
                    },
                ],
            }
        ],
        "policy_break_count": 1,
    }
)

_MULTI_SECRET_TWO_LINES_PATCH = """@@ -0,0 +2 @@
+FacebookAppId = 294790898041575;
+FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;

"""

_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": "Facebook Access Token",
                "detector_name": "facebook_access_token",
                "detector_group_name": "facebook_access_token",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/facebook_access_token",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041575",
                        "index_start": 31,
                        "index_end": 45,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                        "index_start": 69,
                        "index_end": 100,
                        "type": "client_secret",
                    },
                ],
            }
        ],
        "policy_break_count": 1,
    }
)

_MULTILINE_SECRET = """-----BEGIN RSA PRIVATE KEY-----
+MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
+bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
+NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
+TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
+22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
+bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
+RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
+-----END RSA PRIVATE KEY-----"""

_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": "RSA Private Key",
                "detector_name": "private_key_rsa",
                "detector_group_name": "private_key_rsa",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/private_key_rsa",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": _MULTILINE_SECRET,  # noqa
                        "index_start": 42,
                        "index_end": 543,
                        "type": "apikey",
                    }
                ],
            }
        ],
        "policy_break_count": 1,
    }
)

_SIMPLE_SECRET_MULTILINE_PATCH = (
    """@@ -0,0 +1,29 @@
+PrivateKeyRsa:
+- text: """
    + _MULTILINE_SECRET
)


_ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policy_breaks": [
            {
                "type": "Facebook Access Token",
                "detector_name": "facebook_access_token",
                "detector_group_name": "facebook_access_token",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/facebook_access_token",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041573",
                        "line_start": 2,
                        "line_end": 2,
                        "index_start": 35,
                        "index_end": 49,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4371",
                        "line_start": 2,
                        "line_end": 2,
                        "index_start": 53,
                        "index_end": 84,
                        "type": "client_secret",
                    },
                ],
            },
            {
                "type": "RSA Private Key",
                "detector_name": "private_key_rsa",
                "detector_group_name": "private_key_rsa",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/private_key_rsa",
                "policy": "Secrets detection",
                "matches": [
                    {
                        "line_start": 2,
                        "match": _MULTILINE_SECRET,
                        "index_start": 86,
                        "index_end": 585,
                        "type": "apikey",
                        "line_end": 10,
                    }
                ],
            },
            {
                "type": "SendGrid Key",
                "detector_name": "sendgrid",
                "detector_group_name": "sendgrid_key",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/sendgrid_key",
                "policy": "Secrets detection",
                "matches": [
                    {
                        "line_start": 10,
                        "match": "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",  # noqa
                        "index_start": 594,
                        "index_end": 662,
                        "type": "apikey",
                        "line_end": 10,
                    }
                ],
            },
        ],
        "policies": ["Filenames", "File extensions", "Secrets detection"],
        "policy_break_count": 2,
    }
)

_ONE_LINE_AND_MULTILINE_PATCH_CONTENT = """@@ -0,0 +1,29 @@
+FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
+MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
+bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
+NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
+TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
+22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
+bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
+RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
+-----END RSA PRIVATE KEY----- token: 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
"""  # noqa

_ONE_LINE_AND_MULTILINE_PATCH = (
    """commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 A\0test\0\0diff --git a/test b/test
new file mode 100644
index 0000000..b80e3df
--- /dev/null
+++ b/test
"""
    + _ONE_LINE_AND_MULTILINE_PATCH_CONTENT
)

_NO_SECRET_PATCH = """commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 A\0test\0\0diff --git a/test b/test
new file mode 100644
index 0000000..b80e3df
--- /dev/null
+++ b/test
@@ -0,0 +1 @@
+this is a patch without secret
"""

"""
Indices for _SECRET_RAW_FILE
                    0         1         2         3         4         5         6         7         8
                    012345678901234567890123456789012345678901234567890123456789012345678901234567890
"""
_SECRET_RAW_FILE = '+sg_key = "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";\n'

_SINGLE_ADD_PATCH = """commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 A\0test\0\0diff --git a/test b/test
new file mode 100644
index 0000000..3c9af3f
--- /dev/null
+++ b/test
@@ -0,0 +1 @@
+sg_key = "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";
"""
"""
Indices for _SINGLE_ADD_PATCH.
0         1         2         3         4         5         6         7         8
012345678901234567890123456789012345678901234567890123456789012345678901234567890
"""

_SINGLE_MOVE_PATCH = """
commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 M\0test\0\0diff --git a/test b/test
index 3c9af3f..b0ce1c7 100644
--- a/test
+++ b/test
@@ -150 +150,2 @@
+something
 sg_key = "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";
"""

_SINGLE_DELETE_PATCH = """commit 9537b6343a81f88d471e93f20ffb2e2665bbab00
Author: GitGuardian Owl <owl@example.com>
Date:   Thu Aug 18 18:20:21 2022 +0200

A message

:000000 100644 0000000 e965047 D\0test\0\0diff --git a/test b/test
index b0ce1c7..deba01f 100644
--- a/test
+++ b/test
@@ -1,2 +1 @@
 something
-sg_key = "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";
"""

TWO_POLICY_BREAKS = ScanResult.SCHEMA.load(
    {
        "policy_breaks": [
            {
                "type": "RSA Private Key",
                "detector_name": "private_key_rsa",
                "detector_group_name": "private_key_rsa",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/private_key_rsa",
                "policy": "Secrets detection",
                "matches": [
                    {
                        "line_start": 2,
                        "match": _MULTILINE_SECRET,
                        "index_start": 86,
                        "index_end": 585,
                        "type": "apikey",
                        "line_end": 10,
                    }
                ],
            },
            {
                "type": "SendGrid Key",
                "detector_name": "sendgrid",
                "detector_group_name": "sendgrid_key",
                "documentation_url": "https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/sendgrid_key",
                "policy": "Secrets detection",
                "matches": [
                    {
                        "line_start": 10,
                        "match": "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",  # noqa
                        "index_start": 594,
                        "index_end": 662,
                        "type": "apikey",
                        "line_end": 10,
                    }
                ],
            },
        ],
        "policies": ["Filenames", "File extensions", "Secrets detection"],
        "policy_break_count": 2,
    }
)
_SINGLE_LINE_SECRET_FILE = f"""\
apikey = "{GG_TEST_TOKEN}";
"""

_MULTILINE_SECRET_FILE = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
-----END RSA PRIVATE KEY-----""".replace(
    "\r\n", "\n"
)

_ONE_LINE_AND_MULTILINE_FILE = """
FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
-----END RSA PRIVATE KEY----- token: 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
"""

# Docker example constants
DOCKER_EXAMPLE_PATH = DATA_PATH / "docker-example.tar.xz"
DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH = (
    DATA_PATH / "docker-incomplete-manifest-example.tar.xz"
)
DOCKER_EXAMPLE_TAR_GZ_LAYER_PATH = DATA_PATH / "docker-tar-gz-layer.tar.xz"

# Format is { layer_id: { path: content }}
DOCKER_EXAMPLE_LAYER_FILES = {
    "sha256:4e850fb0fe03eae7a9a505d114b342ecdf7fd6e5a3ed2a1967e40083d63c7abe": {
        "/app/file_one": "Hello, I am the first file!\n"
    },
    "sha256:f1c86b269b6a35c2158e8cd69b5e276d6c238272adcdd44efa21e5d79d099ddb": {
        "/app/file_three.sh": "echo Life is beautiful.\n",
        "/app/file_two.py": """print("Hi! I'm the second file but I'm happy.")\n""",
    },
}


def _filter_vcr_response(response: Dict[str, Any]) -> Dict[str, Any]:
    # Read content-type
    headers = response["headers"]
    for name in ("content-type", "Content-Type"):
        try:
            content_type = headers[name][0]
            break
        except KeyError:
            pass
    else:
        # No content-type, let's assume it's not JSON
        return response

    # Remove token returned by calls to https://api.gitguardian.com/v1/auth/jwt.
    # Unfortunately we don't have the URL of the request at this point. We only remove
    # the token if it's the only field. If we don't we break honeytoken cassettes.
    if content_type == "application/json":
        content = json.loads(response["body"]["string"])
        if isinstance(content, dict) and list(content.keys()) == ["token"]:
            content["token"] = "<REDACTED>"
            response["body"]["string"] = json.dumps(content).encode()
    return response


my_vcr = vcr.VCR(
    cassette_library_dir=join(dirname(realpath(__file__)), "cassettes"),
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["method", "url"],
    serializer="yaml",
    record_mode="once",
    filter_headers=["Authorization"],
    before_record_response=_filter_vcr_response,
)


@pytest.fixture(scope="session", autouse=True)
def _ensure_gitguardian_api_key():
    """
    Many VCR-based tests expect GITGUARDIAN_API_KEY to be set, set to a dummy one if
    it's not
    """
    if "GITGUARDIAN_API_KEY" not in os.environ:
        warnings.warn(
            "GITGUARDIAN_API_KEY is not set, recording VCR cassettes won't work."
        )
        os.environ["GITGUARDIAN_API_KEY"] = "not-a-real-key"


@pytest.fixture(scope="session")
def client(_ensure_gitguardian_api_key) -> GGClient:
    api_key = os.environ["GITGUARDIAN_API_KEY"]

    if "GITGUARDIAN_API_URL" in os.environ:  # deprecated
        base_uri = os.environ["GITGUARDIAN_API_URL"]
    else:
        instance_url = os.getenv(
            "GITGUARDIAN_INSTANCE", "https://dashboard.gitguardian.com"
        )
        base_uri = dashboard_to_api_url(instance_url)

    return GGClient(api_key, base_uri)


@pytest.fixture
def no_api_key(monkeypatch):
    """Remove GITGUARDIAN_API_KEY from the environment, useful to test anonymous use"""
    monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)


@pytest.fixture(scope="session")
def cache() -> Cache:
    c = Cache()
    c.purge()
    return c


@pytest.fixture()
def cli_runner():
    return CliRunner()


@pytest.fixture(scope="function")
def cli_fs_runner(cli_runner):
    with cli_runner.isolated_filesystem():
        yield cli_runner


@pytest.fixture(scope="function")
def isolated_fs(fs):
    # isolate fs but include CA bundle for https validation
    fs.add_real_directory(os.path.dirname(extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH)))
    # add cassettes dir
    cassettes_dir = join(dirname(realpath(__file__)), "cassettes")
    fs.add_real_directory(cassettes_dir)
    # Add a fake OS-release file. It describes a linux OS
    mock_contents = """ID="ubuntu"\nVERSION_ID="22.04"\n"""
    f = fs.create_file("/etc/os-release")
    f.set_contents(mock_contents)


def write_text(filename: Union[str, Path], content: str):
    """Create a text file named `filename` with content `content.
    Create any missing dirs if necessary.

    Note that using `write_bytes(content.encode())` ensures the
    same content is created, independently of the OS
    (whereas using Path.write_text creates different line ends depending on the OS)
    """
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode())


def write_yaml(filename: Union[str, Path], data: Any):
    """Save data as a YAML file in `filename`, using `write_text()`"""
    write_text(filename, yaml.dump(data))


def assert_invoke_exited_with(result: Result, exit_code: int):
    msg = f"""
    Expected code {exit_code}, got {result.exit_code}.

    stdout:
    {result.stdout}

    stderr:
    {result.stderr if result.stderr_bytes is not None else ""}
    """
    assert result.exit_code == exit_code, msg


def assert_invoke_ok(result: Result):
    assert_invoke_exited_with(result, 0)


def make_fake_path_inaccessible(fs: FakeFilesystem, path: Union[str, Path]):
    """
    Make `path` inaccessible inside `fs`. This is useful to test IO permission errors.
    """

    # `force_unix_mode` is required for Windows.
    # See <https://pytest-pyfakefs.readthedocs.io/en/latest/usage.html#set-file-as-inaccessible-under-windows>
    fs.chmod(path, 0o0000, force_unix_mode=True)


@pytest.fixture(autouse=True)
def clear_cache():
    _get_git_path.cache_clear()
    _git_rev_parse_absolute.cache_clear()
    read_git_file.cache_clear()


@pytest.fixture(autouse=True)
def _reset_ui_fixture():
    """
    Enabling debug mode has global side effects. Reset it to ensure a test touching the
    log or debug configuration does not affect other tests.
    """
    reset()


SECRET_INCIDENT_MOCK = SecretIncident.from_dict(
    {
        "id": 42,
        "date": "2024-09-04T16:00:48.956235+00:00",
        "detector": {
            "name": "detector",
            "display_name": "Detector",
            "nature": "specific",
            "family": "Api",
            "detector_group_name": "detector_group",
            "detector_group_display_name": "Detector Group",
        },
        "secret_hash": "NpQakTjuW7LlWWgeHOR5VewWfLbUtKn1bZ3EDrLLw7aMf26zyCrzdQOwnLqJOGTb",
        "hmsl_hash": "0483663d03dc4ea2c2bfb73d0a4a8bc6f2035d911f3a7d210a16e8314413c29e",
        "gitguardian_url": "https://dashboard.staging.gitguardian.tech/workspace/1/incidents/42",
        "regression": False,
        "status": "TRIGGERED",
        "assignee_id": None,
        "assignee_email": None,
        "occurrences_count": 1,
        "secret_presence": {
            "files_requiring_code_fix": 1,
            "files_pending_merge": 0,
            "files_fixed": 0,
            "outside_vcs": 0,
            "removed_outside_vcs": 0,
            "in_vcs": 1,
            "removed_in_vcs": 0,
        },
        "ignore_reason": None,
        "triggered_at": "2024-09-04T16:00:48.956235+00:00",
        "ignored_at": None,
        "ignorer_id": None,
        "ignorer_api_token_id": None,
        "resolver_id": None,
        "resolver_api_token_id": None,
        "secret_revoked": False,
        "severity": "high",
        "validity": "invalid",
        "resolved_at": None,
        "share_url": None,
        "tags": [],
        "feedback_list": [],
        "occurrences": [],
    }
)
