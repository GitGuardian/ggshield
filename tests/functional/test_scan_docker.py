import subprocess

import pytest
from conftest import FUNCTESTS_DATA_PATH
from utils import assert_is_valid_json, run_ggshield_scan


def build_image(name: str) -> None:
    subprocess.run(
        ["docker", "build", "-t", name, "."], cwd=FUNCTESTS_DATA_PATH / name, check=True
    )


def test_scan_docker() -> None:
    run_ggshield_scan("docker", "ubuntu:20.04")


def test_scan_docker_json() -> None:
    proc = run_ggshield_scan("--json", "docker", "ubuntu:20.04")
    assert_is_valid_json(proc.stdout)


@pytest.mark.parametrize(
    "image_name",
    (
        "docker-leaking-in-env",
        "docker-leaking-in-layer",
    ),
)
def test_scan_docker_find_secret(image_name: str) -> None:
    build_image(image_name)
    proc = run_ggshield_scan("docker", image_name, expected_code=1)
    print(proc.stdout)
    print(proc.stderr)
