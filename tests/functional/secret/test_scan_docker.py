import os
import shutil
import subprocess
from pathlib import Path
from string import Template

import pytest

from tests.conftest import GG_VALID_TOKEN
from tests.functional.conftest import FUNCTESTS_DATA_PATH
from tests.functional.utils import (
    assert_is_valid_json,
    recreate_censored_content,
    run_ggshield_scan,
)


HAS_DOCKER = shutil.which("docker") is not None

TEST_DOCKER_IMAGE = os.getenv("GGTEST_DOCKER_IMAGE", "ubuntu:20.04")


pytestmark = pytest.mark.skipif(not HAS_DOCKER, reason="These tests require Docker")


def build_image(tmp_path: Path, name: str) -> None:
    image_path = tmp_path / "image"
    shutil.copytree(FUNCTESTS_DATA_PATH / name, image_path)

    variables = {
        "TEST_DOCKER_IMAGE": TEST_DOCKER_IMAGE,
        "GG_VALID_TOKEN": GG_VALID_TOKEN,
    }
    for path in image_path.rglob("*"):
        if not path.is_file():
            continue
        tmpl = Template(path.read_text())
        content = tmpl.substitute(variables)
        path.write_text(content)

    subprocess.run(["docker", "build", "-t", name, "."], cwd=image_path, check=True)


def test_scan_docker() -> None:
    run_ggshield_scan("docker", TEST_DOCKER_IMAGE)


def test_scan_docker_json() -> None:
    proc = run_ggshield_scan("--json", "docker", TEST_DOCKER_IMAGE)
    assert_is_valid_json(proc.stdout)


@pytest.mark.parametrize(
    "image_name",
    (
        "docker-leaking-in-env",
        "docker-leaking-in-layer",
    ),
)
def test_scan_docker_find_secret(tmp_path: Path, image_name: str) -> None:
    build_image(tmp_path, image_name)
    proc = run_ggshield_scan("docker", image_name, expected_code=1, cwd=tmp_path)

    assert (
        recreate_censored_content(f"token={GG_VALID_TOKEN}", GG_VALID_TOKEN)
        in proc.stdout
    )
