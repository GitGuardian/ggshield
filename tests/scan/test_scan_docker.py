import re
import subprocess
from pathlib import Path
from typing import Dict
from unittest.mock import patch

import click
import pytest

from ggshield.scan.docker import (
    InvalidDockerArchiveException,
    _get_config,
    _should_scan_layer,
    docker_pull_image,
    docker_save_to_tmp,
    get_files_from_docker_archive,
)
from tests.conftest import DATA_PATH


DOCKER_EXAMPLE_PATH = DATA_PATH / "docker-example.tar.xz"
DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH = (
    DATA_PATH / "docker-incomplete-manifest-example.tar.xz"
)


class ManifestMock:
    def read(self, amount: int = None) -> bytes:
        return '[{"Config": "8b907fee27ad927c595fcf873c8256796cab27e7a3fb4bf3952308a76ad791c4.json"}]'.encode(  # noqa: E501
            "utf-8"
        )


class TarMock:
    def __init__(self, members: Dict[str, str], *args, **kwargs):
        self.members = members

    def extractfile(self, member: str):
        if "8b907fee27ad927c595fcf873c8256796cab27e7a3fb4bf3952308a76ad791c4" in member:
            return None
        return self.members.get(member, None)

    def getmember(self, member: str):
        return member if self.members.get(member, None) else None


class TestDockerScan:
    @pytest.mark.parametrize(
        ["op", "want"],
        [
            pytest.param(
                "/bin/sh -c #(nop) COPY dir:xxx in / ",
                True,
            ),
            pytest.param("/bin/sh -c #(nop) ADD dir:xxx in / ", True),
            pytest.param(
                '/bin/sh -c #(nop)  CMD ["/usr/bin/bash"',
                False,
            ),
        ],
    )
    def test_should_scan_layer(self, op: str, want: bool):
        assert _should_scan_layer({"created_by": op}) is want

    @pytest.mark.parametrize(
        ["members", "match"],
        [
            pytest.param({}, "No manifest file found."),
            pytest.param(
                {"manifest.json": ManifestMock()},
                "No config file found.",
            ),
            pytest.param(
                {
                    "manifest.json": ManifestMock(),
                    "8b907fee27ad927c595fcf873c8256796cab27e7a3fb4bf3952308a76ad791c4.json": "layer file",  # noqa: E501
                },  # noqa: E501
                "Config file could not be extracted.",
            ),
        ],
    )
    def test_get_config(self, members, match):
        tarfile = TarMock(members)
        with pytest.raises(InvalidDockerArchiveException, match=match):
            _get_config(tarfile)

    @pytest.mark.parametrize(
        "image_path", [DOCKER_EXAMPLE_PATH, DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH]
    )
    def test_get_files_from_docker_archive(self, image_path: Path):
        files = get_files_from_docker_archive(image_path)

        expected_files = {
            "Dockerfile or build-args": None,
            "64a345482d74ea1c0699988da4b4fe6cda54a2b0ad5da49853a9739f7a7e5bbc:/app/file_one": "Hello, I am the first file!\n",  # noqa: E501
            "2d185b802fb3c2e6458fe1ac98e027488cd6aedff2e3d05eb030029c1f24d60f:/app/file_three.sh": "echo Life is beautiful.\n",  # noqa: E501
            "2d185b802fb3c2e6458fe1ac98e027488cd6aedff2e3d05eb030029c1f24d60f:/app/file_two.py": """print("Hi! I'm the second file but I'm happy.")\n""",  # noqa: E501
        }

        assert set(files.filenames) == {str(file_path) for file_path in expected_files}

        file_dict = {x.filename: x for x in files.files}
        for file_path, expected_content in expected_files.items():
            file = file_dict[str(file_path)]
            assert expected_content is None or file.document == expected_content


DOCKER_TIMEOUT = 12


class TestDockerPull:
    def test_docker_pull_image_success(self):
        with patch("subprocess.run") as call:
            docker_pull_image("ggshield-non-existant", DOCKER_TIMEOUT)
            call.assert_called_once_with(
                ["docker", "pull", "ggshield-non-existant"],
                check=True,
                timeout=DOCKER_TIMEOUT,
            )

    def test_docker_pull_image_non_exist(self):
        with patch(
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, cmd=[])
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match='Image "ggshield-non-existant" not found',
            ):
                docker_pull_image("ggshield-non-existant", DOCKER_TIMEOUT)

    def test_docker_pull_image_timeout(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=[], timeout=DOCKER_TIMEOUT),
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match='docker pull ggshield-non-existant" timed out',
            ):
                docker_pull_image("ggshield-non-existant", DOCKER_TIMEOUT)


class TestDockerSave:
    TMP_ARCHIVE = Path("/tmp/as/archive.tar")

    def test_docker_save_image_success(self):
        with patch("subprocess.run") as call:
            docker_save_to_tmp(
                "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
            )
            call.assert_called_once_with(
                [
                    "docker",
                    "save",
                    "ggshield-non-existant",
                    "-o",
                    str(self.TMP_ARCHIVE),
                ],
                check=True,
                stderr=-1,
                timeout=DOCKER_TIMEOUT,
            )

    def test_docker_save_image_does_not_exist(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(
                1, cmd=[], stderr="reference does not exist".encode("utf-8")
            ),
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match='Image "ggshield-non-existant" not found',
            ):
                docker_save_to_tmp(
                    "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
                )

    def test_docker_save_image_need_pull(self):
        """
        GIVEN a Docker image we do not have locally
        WHEN we try to save it
        THEN we first pull it and then save it

        This test expects the following calls to `docker` commands:

        - docker save <image_name> -o <something>
          -> Fake failure
        - docker pull <image_name>
          -> Fake success
        - docker save <image_name> -o <something>
          -> Fake success
        """
        with patch(
            "subprocess.run",
            side_effect=[
                subprocess.CalledProcessError(
                    1, cmd=[], stderr="reference does not exist".encode("utf-8")
                ),
                None,
                None,
            ],
        ):
            docker_save_to_tmp(
                "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
            )

    def test_docker_save_image_fails(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(
                1, cmd=[], stderr="docker failed weirdly".encode("utf-8")
            ),
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match="Unable to save docker archive:",
            ):
                docker_save_to_tmp(
                    "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
                )

    def test_docker_save_image_timeout(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=[], timeout=DOCKER_TIMEOUT),
        ):
            expected_msg = f'Command "docker save ggshield-non-existant -o {str(self.TMP_ARCHIVE)}" timed out'  # noqa: E501
            with pytest.raises(
                click.exceptions.ClickException,
                match=re.escape(expected_msg),
            ):
                docker_save_to_tmp(
                    "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
                )
