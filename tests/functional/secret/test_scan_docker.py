import json
import os
import shutil
import subprocess
from pathlib import Path
from string import Template

import jsonschema
import pytest

from ggshield.core.dirs import get_cache_dir
from tests.conftest import GG_VALID_TOKEN, skipwindows
from tests.functional.conftest import FUNCTESTS_DATA_PATH, requires_docker
from tests.functional.utils import recreate_censored_content, run_ggshield_scan


TEST_DOCKER_IMAGE = os.getenv("GGTEST_DOCKER_IMAGE", "ubuntu:20.04")


pytestmark = requires_docker()


@pytest.fixture()
def clear_layer_cache():
    shutil.rmtree(get_cache_dir() / "docker", ignore_errors=True)


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


def test_scan_docker(clear_layer_cache) -> None:
    run_ggshield_scan("docker", TEST_DOCKER_IMAGE)


def test_scan_docker_json(clear_layer_cache, secret_json_schema) -> None:
    # GIVEN a scan of a docker image
    proc = run_ggshield_scan("docker", TEST_DOCKER_IMAGE, "--json")
    # THEN the output is a valid JSON, matching the secret schema
    dct = json.loads(proc.stdout)
    jsonschema.validate(dct, secret_json_schema)


@pytest.mark.parametrize(
    "image_name",
    (
        "docker-leaking-in-env",
        "docker-leaking-in-layer",
    ),
)
def test_scan_docker_find_secret(
    clear_layer_cache, tmp_path: Path, image_name: str
) -> None:
    build_image(tmp_path, image_name)
    proc = run_ggshield_scan("docker", image_name, expected_code=1, cwd=tmp_path)

    assert (
        recreate_censored_content(f"token={GG_VALID_TOKEN}", GG_VALID_TOKEN)
        in proc.stdout
    )


# Skip this test on Windows because on the CI the generated Docker image contains only
# one layer, so there is no caching.
# This is most likely related to the fact that the CI uses Windows Docker engine: the
# same test passes on a Windows machine using Linux Docker engine.
@skipwindows
def test_scan_docker_uses_cache(clear_layer_cache, tmp_path: Path) -> None:
    """
    GIVEN a docker image with a secret in the last layer
    WHEN scanned a second time
    THEN only the last layer is re-scanned
    """
    image_name = "docker-leaking-in-layer"
    scanning_snippet = "Scanning layer"
    skipping_snippet = "Skipping layer"

    build_image(tmp_path, image_name)
    proc = run_ggshield_scan("docker", image_name, expected_code=1, cwd=tmp_path)

    scanning_occurrences1 = proc.stderr.count(scanning_snippet)
    skipping_occurrences = proc.stderr.count(skipping_snippet)

    assert skipping_occurrences == 0

    proc = run_ggshield_scan("docker", image_name, expected_code=1, cwd=tmp_path)
    scanning_occurrences2 = proc.stderr.count(scanning_snippet)
    skipping_occurrences = proc.stderr.count(skipping_snippet)

    assert skipping_occurrences == 1
    assert scanning_occurrences2 == scanning_occurrences1 - 1
