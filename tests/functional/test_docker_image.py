import os
import subprocess

import pytest

from tests.conftest import skipwindows
from tests.functional.conftest import REPO_PATH, requires_docker


pytestmark = [requires_docker, skipwindows]


@pytest.fixture(scope="module")
def docker_image():
    """Build our Docker image"""
    image_name = "ggshield_func_test"
    build_cmd = ["docker", "build", "-t", image_name, str(REPO_PATH)]
    subprocess.run(build_cmd, check=True)
    return image_name


@pytest.mark.parametrize(
    ("mount_dir", "set_work_dir"),
    (
        ("/data", False),
        ("/src", True),
    ),
)
def test_docker_image_can_use_git(docker_image, mount_dir, set_work_dir) -> None:
    """
    GIVEN gitguardian/ggshield Docker image
    AND a git working tree mounted in `mount_dir`
    WHEN running a `ggshield secret scan` command which uses git on `mount_dir`
    THEN the scan succeeds without no `dubious directory` errors
    """
    src_dir = os.getcwd()
    extra_args = ["-w", mount_dir] if set_work_dir else []

    run_cmd = [
        "docker",
        "run",
        "-e",
        "GITGUARDIAN_API_KEY",
        "-v",
        f"{src_dir}:{mount_dir}",
        *extra_args,
        docker_image,
        "ggshield",
        "secret",
        "scan",
        "commit-range",
        "HEAD~2..",
    ]
    subprocess.run(run_cmd, check=True)
