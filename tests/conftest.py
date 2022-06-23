import os
import platform
from os.path import dirname, join, realpath
from pathlib import Path
from typing import Any

import pytest
import vcr
import yaml
from click.testing import CliRunner, Result
from pygitguardian import GGClient
from pygitguardian.models import ScanResult
from requests.utils import DEFAULT_CA_BUNDLE_PATH, extract_zipped_paths

from ggshield.core.cache import Cache


os.environ.setdefault("PYTHONBREAKPOINT", "ipdb.set_trace")


skipwindows = pytest.mark.skipif(
    platform.system() == "Windows" and not os.environ.get("DISABLE_SKIPWINDOWS"),
    reason="Skipped on Windows for now, define DISABLE_SKIPWINDOWS environment variable to unskip",
)


def is_macos():
    return platform.system() == "Darwin"


DATA_PATH = Path(__file__).parent.absolute() / "data"


_MULTIPLE_SECRETS_PATCH = """@@ -0,0 +1,2 @@
+FacebookAppKeys :
+String docker run --name geonetwork -d \
            -p 8080:8080 -e MYSQL_HOST=google.com \
            -e MYSQL_PORT=5434 -e MYSQL_USERNAME=root \
            -e MYSQL_PASSWORD=m42ploz2wd geonetwork
"""

_MULTIPLE_SECRETS = (
    """diff --git a/test.txt b/test.txt
new file mode 100644
index 0000000..b80e3df
--- /dev/null
+++ b/test
"""
    + _MULTIPLE_SECRETS_PATCH
)

_MULTIPLE_SECRETS_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policy_break_count": 1,
        "policies": ["Secrets detection", "File extensions", "Filenames"],
        "policy_breaks": [
            {
                "type": "MySQL Assignment",
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

# This long token is a test token, always reported as an uncheckable secret
GG_TEST_TOKEN = (
    "8a784aab7090f6a4ba3b9f7a6594e2e727007a26590b58ed314e4b9ed4536479sRZlRup3xvtMVfiHWA"
    "anbe712Jtc3nY8veZux5raL1bhpaxiv0rfyhFoAIMZUCh2Njyk7gRVsSQFPrEphSJnxa16SIdWKb03sRft"
    "770LUTTYTAy3IM18A7Su4HjiHlGA9ihLj9ou3luadfRAATlKH6kAZwTw289Kq9uip67zxyWkUJdh6PTeFp"
    "MgCh3AhHcZ21VeZHlu12345"
)

# This is another test token, this one is always report as a valid secret
GG_VALID_TOKEN = "ggtt-v-12345azert"  # ggignore

UNCHECKED_SECRET = (
    "diff --git a/test.txt b/test.txt\n"
    "new file mode 100644\n"
    "index 0000000..b80e3df\n"
    "--- /dev/null\n"
    "+++ b/test\n"
    "@@ -0,0 +2 @@\n"
    "+# gg token\n"
    f'+apikey = "{GG_TEST_TOKEN}";\n'
)

VALID_SECRET = (
    "diff --git a/test.txt b/test.txt\n"
    "new file mode 100644\n"
    "index 0000000..b80e3df\n"
    "--- /dev/null\n"
    "+++ b/test\n"
    "@@ -0,0 +2 @@\n"
    "+# gg token\n"
    f'+apikey = "{GG_VALID_TOKEN}";\n'
)

_SIMPLE_SECRET = UNCHECKED_SECRET

_SIMPLE_SECRET_TOKEN = "368ac3edf9e850d1c0ff9d6c526496f8237ddf91"
_SIMPLE_SECRET_PATCH = f"""@@ -0,0 +1 @@
+github_token: {_SIMPLE_SECRET_TOKEN}
"""
_SIMPLE_SECRET_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": "GitHub Token",
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
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": ".env",
                "policy": "Filenames",
                "matches": [{"type": "filename", "match": ".env"}],
            },
            {
                "type": "GitHub Token",
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
        "policy_break_count": 2,
    }
)

_MULTI_SECRET_ONE_LINE_PATCH = """@@ -0,0 +1 @@
+FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;

"""

_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT = ScanResult.SCHEMA.load(
    {
        "policies": ["File extensions", "Filenames", "Secrets detection"],
        "policy_breaks": [
            {
                "type": "Facebook Access Tokens",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041575",
                        "index_start": 31,
                        "index_end": 46,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                        "index_start": 68,
                        "index_end": 100,
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
                "type": "Facebook Access Tokens",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041575",
                        "index_start": 26,
                        "index_end": 41,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                        "index_start": 44,
                        "index_end": 76,
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
                "type": "Facebook Access Tokens",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041575",
                        "index_start": 31,
                        "index_end": 46,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                        "index_start": 69,
                        "index_end": 101,
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
                "type": "Facebook Access Tokens",
                "policy": "Secrets Detection",
                "matches": [
                    {
                        "match": "294790898041573",
                        "line_start": 2,
                        "line_end": 2,
                        "index_start": 34,
                        "index_end": 49,
                        "type": "client_id",
                    },
                    {
                        "match": "ce3f9f0362bbe5ab01dfc8ee565e4371",
                        "line_start": 2,
                        "line_end": 2,
                        "index_start": 52,
                        "index_end": 84,
                        "type": "client_secret",
                    },
                ],
            },
            {
                "type": "RSA Private Key",
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
    """diff --git a/test.txt b/test.txt
new file mode 100644
index 0000000..b80e3df
--- /dev/null
+++ b/test
"""
    + _ONE_LINE_AND_MULTILINE_PATCH_CONTENT
)

_NO_SECRET = (
    "diff --git a/test.txt b/test.txt\n"
    "new file mode 100644\n"
    "index 0000000..b80e3df\n"
    "--- /dev/null\n"
    "+++ b/test\n"
    "@@ -0,0 +1 @@\n"
    "+this is a patch without secret\n"
)


_SECRET_RAW_FILE = '+sg_key = "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";\n'

_SINGLE_ADD_PATCH = (
    "diff --git a/test b/test\n"
    "new file mode 100644\n"
    "index 0000000..3c9af3f\n"
    "--- /dev/null\n"
    "+++ b/test\n"
    "@@ -0,0 +1 @@\n"
    '+sg_key = "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";\n'  # noqa
)

_SINGLE_MOVE_PATCH = (
    "diff --git a/test b/test\n"
    "index 3c9af3f..b0ce1c7 100644\n"
    "--- a/test\n"
    "+++ b/test\n"
    "@@ -1 +1,2 @@\n"
    "+something\n"
    ' sg_key = "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";\n'
)

_SINGLE_DELETE_PATCH = (
    "diff --git a/test b/test\n"
    "index b0ce1c7..deba01f 100644\n"
    "--- a/test\n"
    "+++ b/test\n"
    "@@ -1,2 +1 @@\n"
    " something\n"
    '-sg_key = "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";\n'  # noqa
)
_PATCH_WITH_NONEWLINE_BEFORE_SECRET = """
diff --git a/artifactory b/artifactory
index 2ace9c7..4c7699d 100644
--- a/artifactory
+++ b/artifactory
@@ -1,3 +1,3 @@
 some line
 some other line
-deleted line
\\ No newline at end of file
+sg_key = "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"
\\ No newline at end of file
"""

_IAC_SINGLE_VULNERABILITY = """
resource "aws_alb_listener" "bad_example" {
  protocol = "HTTP"
}
"""

_IAC_MULTIPLE_VULNERABILITIES = """
resource "aws_security_group" "bad_example" {
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

 resource "aws_security_group_rule" "bad_example" {
  type = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

"""

_IAC_NO_VULNERABILITIES = """
resource "aws_network_acl_rule" "bad_example" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "12.13.14.15"
}
"""

my_vcr = vcr.VCR(
    cassette_library_dir=join(dirname(realpath(__file__)), "cassettes"),
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["method", "url"],
    serializer="yaml",
    record_mode="once",
    filter_headers=["Authorization"],
)


@pytest.fixture(scope="session")
def client() -> GGClient:
    api_key = os.getenv("TEST_GITGUARDIAN_API_KEY", "1234567890")
    base_uri = os.getenv("TEST_GITGUARDIAN_API_URL", "https://api.gitguardian.com")
    return GGClient(api_key, base_uri)


@pytest.fixture(scope="session")
def cache() -> Cache:
    c = Cache()
    c.purge()
    return c


@pytest.fixture()
def cli_runner():
    os.environ["GITGUARDIAN_API_KEY"] = os.getenv(
        "TEST_GITGUARDIAN_API_KEY", "1234567890"
    )
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


def write_text(filename: str, content: str):
    """Create a text file named `filename` with content `content.
    Create any missing dirs if necessary."""
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def write_yaml(filename: str, data: Any):
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
