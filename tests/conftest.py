import os
import platform

import pytest


# This is a test token, it is always reported as a valid secret
GG_VALID_TOKEN = "ggtt-v-12345azert"  # ggignore


skipwindows = pytest.mark.skipif(
    platform.system() == "Windows" and not os.environ.get("DISABLE_SKIPWINDOWS"),
    reason="Skipped on Windows for now, define DISABLE_SKIPWINDOWS environment variable to unskip",
)
