import os
import platform

import pytest


# This is a test token, it is always reported as a valid secret
GG_VALID_TOKEN = "ggtt-v-12345azert"  # ggignore


def is_windows():
    return platform.system() == "Windows"


skipwindows = pytest.mark.skipif(
    is_windows() and not os.environ.get("DISABLE_SKIPWINDOWS"),
    reason="Skipped on Windows for now, define DISABLE_SKIPWINDOWS environment variable to unskip",
)


@pytest.fixture(autouse=True)
def do_not_use_real_config_dir(monkeypatch, tmp_path):
    """
    This fixture ensures we do not use the real configuration directory, where
    `ggshield auth` stores credentials.
    """
    monkeypatch.setenv("TEST_CONFIG_DIR", str(tmp_path))


@pytest.fixture(autouse=True)
def do_not_use_real_cache_dir(monkeypatch, tmp_path):
    """
    This fixture ensures we do not use the real cache directory.
    """
    monkeypatch.setenv("TEST_CACHE_DIR", str(tmp_path))
