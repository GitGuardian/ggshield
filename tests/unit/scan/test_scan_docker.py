import re
import subprocess
import tarfile
from pathlib import Path
from typing import Dict
from unittest.mock import patch

import click
import pytest

from ggshield.core.errors import UnexpectedError
from ggshield.scan.docker import (
    DockerImage,
    InvalidDockerArchiveException,
    LayerInfo,
    _get_config,
    _should_scan_layer,
    docker_pull_image,
    docker_save_to_tmp,
)
from tests.unit.conftest import (
    DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH,
    DOCKER_EXAMPLE_LAYER_FILES,
    DOCKER_EXAMPLE_PATH,
)


class ManifestMock:
    def read(self, amount: int = None) -> bytes:
        return b'[{"Config": "8b907fee27ad927c595fcf873c8256796cab27e7a3fb4bf3952308a76ad791c4.json"}]'


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
        assert _should_scan_layer(LayerInfo(filename="dummy", command=op)) is want

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
    def test_docker_archive(self, image_path: Path):
        with tarfile.open(image_path) as archive:
            image = DockerImage(archive)

            # List of (LayerInfo, Files)
            # The filter is here to remove layers with no scannables
            infos_and_layers = list(
                filter(
                    lambda info_and_layer: info_and_layer[1].files,
                    ((x, image.get_layer(x)) for x in image.layer_infos),
                )
            )

            layer_ids = [x.get_id() for x, _ in infos_and_layers]
            assert layer_ids == list(DOCKER_EXAMPLE_LAYER_FILES)

            layers = [l for _, l in infos_and_layers]
            for layer, expected_content_dict in zip(
                layers, DOCKER_EXAMPLE_LAYER_FILES.values()
            ):
                content_dict = {x.path.as_posix(): x.content for x in layer.files}
                assert content_dict == expected_content_dict


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
                click.UsageError,
                match='Image "ggshield-non-existant" not found',
            ):
                docker_pull_image("ggshield-non-existant", DOCKER_TIMEOUT)

    def test_docker_pull_image_timeout(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=[], timeout=DOCKER_TIMEOUT),
        ):
            with pytest.raises(
                UnexpectedError,
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
                    "ggshield-non-existant:latest",
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
                1, cmd=[], stderr=b"reference does not exist"
            ),
        ):
            with pytest.raises(
                click.UsageError,
                match='Image "ggshield-non-existant:latest" not found',
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
                    1, cmd=[], stderr=b"reference does not exist"
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
                1, cmd=[], stderr=b"docker failed weirdly"
            ),
        ):
            with pytest.raises(
                UnexpectedError,
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
            expected_msg = f'Command "docker save ggshield-non-existant:latest -o {str(self.TMP_ARCHIVE)}" timed out'  # noqa: E501
            with pytest.raises(
                UnexpectedError,
                match=re.escape(expected_msg),
            ):
                docker_save_to_tmp(
                    "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
                )
