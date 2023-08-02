import os
import platform
from pathlib import Path

import pytest


# The directory holding ggshield repository checkout
ROOT_DIR = Path(__file__).parent.parent

# This is a test token, it is always reported as a valid secret
GG_VALID_TOKEN = "ggtt-v-12345azert"  # ggignore
GG_VALID_TOKEN_IGNORE_SHA = (
    "56c126cef75e3d17c3de32dac60bab688ecc384a054c2c85b688c1dd7ac4eefd"
)

# This secret must be a secret known by the dashboard running functional tests
KNOWN_SECRET = os.environ.get("TEST_KNOWN_SECRET", "")

# This secret must not be not known by the dashboard running our tests
UNKNOWN_SECRET = os.environ.get("TEST_UNKNOWN_SECRET", "ggtt-v-0frijgo789")  # ggignore


def is_windows():
    return platform.system() == "Windows"


skipwindows = pytest.mark.skipif(
    is_windows() and not os.environ.get("DISABLE_SKIPWINDOWS"),
    reason="Skipped on Windows for now, define DISABLE_SKIPWINDOWS environment variable to unskip",
)


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


@pytest.fixture(autouse=True)
def do_not_use_real_user_dirs(monkeypatch, tmp_path):
    """
    This fixture ensures we do not use real user directories.
    Overridden directories are:
    - the auth configuration directory, where `ggshield auth` stores credentials.
    - the cache directory
    - the home directory
    """
    monkeypatch.setenv("GG_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("GG_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("GG_USER_HOME_DIR", str(tmp_path / "home"))


@pytest.fixture(autouse=True)
def do_not_use_colors(monkeypatch):
    """
    This fixture ensures we do not print colors for easier testing.
    """
    monkeypatch.setenv("NO_COLOR", "1")
