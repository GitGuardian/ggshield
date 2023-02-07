import shutil
from pathlib import Path

import pytest


FUNCTESTS_DATA_PATH = Path(__file__).parent / "data"

# Path to the root of ggshield repository
REPO_PATH = Path(__file__).parent.parent.parent

HAS_DOCKER = shutil.which("docker") is not None

# Use this as a decorator for tests which call the `docker` binary
requires_docker = pytest.mark.skipif(not HAS_DOCKER, reason="This test requires Docker")
