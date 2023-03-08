import os
import platform

import pytest


# This is a test token, it is always reported as a valid secret
GG_VALID_TOKEN = "ggtt-v-12345azert"  # ggignore


skipwindows = pytest.mark.skipif(
    platform.system() == "Windows" and not os.environ.get("DISABLE_SKIPWINDOWS"),
    reason="Skipped on Windows for now, define DISABLE_SKIPWINDOWS environment variable to unskip",
)


@pytest.fixture(autouse=True)
def do_not_use_real_config_dir(monkeypatch, tmp_path):
    """
    This fixture ensures we do not use the real configuration directory, where
    `ggshield auth` stores credentials.
    """
    monkeypatch.setenv("TEST_CONFIG_DIR", str(tmp_path))
