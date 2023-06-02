import functools
import subprocess
from typing import Any

import pytest

from tests.conftest import ROOT_DIR, skipwindows
from tests.functional.conftest import REPO_PATH, requires_docker


pytestmark = [requires_docker, skipwindows]


def docker(cmd: str, *args: Any) -> None:
    full_cmd = ["docker", cmd] + [str(x) for x in args]
    subprocess.run(full_cmd, check=True)


docker_run = functools.partial(docker, "run")
docker_exec = functools.partial(docker, "exec")


GGSHIELD_SCAN_CMD = ["ggshield", "secret", "scan", "commit-range", "HEAD~2.."]


@pytest.fixture(scope="module")
def docker_image():
    """Build our Docker image"""
    image_name = "ggshield_func_test"
    docker("build", "-t", image_name, REPO_PATH)
    return image_name


@pytest.mark.parametrize(
    ("mount_dir", "set_work_dir"),
    (
        ("/data", False),
        ("/src", True),
    ),
)
def test_docker_image_scan_from_volume(docker_image, mount_dir, set_work_dir) -> None:
    """
    GIVEN gitguardian/ggshield Docker image
    AND a git working tree mounted in `mount_dir`
    WHEN running a `ggshield secret scan` command which uses git on `mount_dir`
    THEN the scan succeeds without `dubious directory` errors
    """
    extra_args = ["-w", mount_dir] if set_work_dir else []

    docker_run(
        "-e",
        "GITGUARDIAN_API_KEY",
        "-v",
        f"{ROOT_DIR}:{mount_dir}",
        *extra_args,
        docker_image,
        *GGSHIELD_SCAN_CMD,
    )


def test_docker_image_scan_gitlab_style(docker_image) -> None:
    """
    GIVEN a Docker container setup like GitLab
    WHEN running a `ggshield secret scan` command in the container
    THEN the scan succeeds without `dubious directory` errors
    """
    container_name = "ggshield_func_test_container"

    # Where the repository is cloned inside the Docker container
    work_dir = "/src"

    try:
        # Start the container in detached mode. Run `tail -f` in it to make
        # sure it does not stop.
        docker_run(
            "--rm", "--name", container_name, "--detach", docker_image, "tail", "-f"
        )

        # Clone the repo inside the running container, as root, like GitLab does
        docker_exec(
            "--user",
            0,
            container_name,
            "git",
            "clone",
            "https://github.com/gitguardian/ggshield",
            "--depth",
            3,
            work_dir,
        )

        # Run the scan
        docker_exec(
            "-e",
            "GITGUARDIAN_API_KEY",
            "-w",
            work_dir,
            container_name,
            *GGSHIELD_SCAN_CMD,
        )
    finally:
        # Stop the container
        docker("stop", "--time", 0, container_name)
