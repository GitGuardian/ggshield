import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.scan import StringScannable
from ggshield.verticals.secret import SecretScanCollection
from ggshield.verticals.secret.docker import DockerImage, LayerInfo, _validate_filepath
from tests.unit.conftest import (
    DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH,
    DOCKER_EXAMPLE_PATH,
    UNCHECKED_SECRET_PATCH,
    assert_invoke_exited_with,
    assert_invoke_ok,
    my_vcr,
)


class TestDockerUtils:
    @pytest.mark.parametrize(
        "filepath, valid",
        (
            ["/usr/bin/secret.py", False],
            ["usr/bin/secret.py", False],
            ["/my/file/secret.py", True],
            ["/my/file/usr/bin/secret.py", True],
            ["/usr/share/nginx/secret.py", True],
            ["/gems/secret.py", True],
            ["/npm-bis/secret.py", True],
            ["/banned/extension/secret.exe", False],
            ["/banned/extension/secret.mng", False],
            ["/banned/extension/secret.tar", False],
            ["/banned/extension/secret.other", True],
        ),
    )
    def test_docker_filepath_validation(self, filepath, valid):
        assert (
            _validate_filepath(
                filepath=filepath,
            )
            is valid
        )


class TestDockerCMD:
    @patch("ggshield.cmd.secret.scan.docker.docker_save_to_tmp")
    @patch("ggshield.cmd.secret.scan.docker.docker_scan_archive")
    def test_docker_scan(
        self, scan_mock: Mock, save_mock, cli_fs_runner: click.testing.CliRunner
    ):
        scan_mock.return_value = SecretScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "docker", "ggshield-non-existant"],
        )
        assert_invoke_ok(result)

    @patch("ggshield.cmd.secret.scan.docker.docker_save_to_tmp")
    @patch("ggshield.cmd.secret.scan.docker.docker_scan_archive")
    def test_docker_scan_abort(
        self, scan_mock: Mock, save_mock: Mock, cli_fs_runner: click.testing.CliRunner
    ):
        save_mock.side_effect = click.exceptions.Abort()
        scan_mock.return_value = SecretScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "docker", "ggshield-non-existant"],
        )
        assert_invoke_ok(result)

        expected_output = ""
        if sys.version_info < (3, 9):
            expected_output += (
                "Warning: Python 3.8 is no longer supported by the Python Software Foundation. "
                "GGShield will soon require Python 3.9 or above to run.\n"
            )
        assert result.output == expected_output

    @patch("ggshield.cmd.secret.scan.docker.docker_save_to_tmp")
    @patch("ggshield.cmd.secret.scan.docker.docker_scan_archive")
    def test_docker_scan_failed_to_save(
        self, scan_mock: Mock, save_mock: Mock, cli_fs_runner: click.testing.CliRunner
    ):
        save_mock.side_effect = click.UsageError(
            'Image "ggshield-non-existant" not found'
        )
        scan_mock.return_value = SecretScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "docker", "ggshield-non-existant"],
        )
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert 'Image "ggshield-non-existant" not found' in result.output

    @patch("ggshield.verticals.secret.docker.DockerImage.open")
    @pytest.mark.parametrize(
        "image_path", [DOCKER_EXAMPLE_PATH, DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH]
    )
    @pytest.mark.parametrize("json_output", (False, True))
    def test_docker_scan_archive(
        self,
        docker_image_open_mock: Mock,
        cli_fs_runner: click.testing.CliRunner,
        image_path: Path,
        json_output: bool,
    ):
        assert image_path.exists()

        layer_info = LayerInfo(
            filename="12345678/layer.tar", command="COPY foo", diff_id="sha256:1234"
        )

        def create_docker_image() -> Mock(spec=DockerImage):
            docker_image = Mock(spec=DockerImage)
            docker_image.config_scannable = StringScannable(
                content="", url="Dockerfile or build-args"
            )
            docker_image.layer_infos = [layer_info]

            scannable = StringScannable(
                content=UNCHECKED_SECRET_PATCH, url="file_secret"
            )
            docker_image.get_layer_scannables.return_value = [scannable]

            return docker_image

        docker_image = create_docker_image()

        docker_image_open_mock.return_value.__enter__.return_value = docker_image

        with my_vcr.use_cassette("test_scan_file_secret"):
            json_arg = ["--json"] if json_output else []
            cli_fs_runner.mix_stderr = False
            result = cli_fs_runner.invoke(
                cli,
                [
                    "-v",
                    "secret",
                    "scan",
                    *json_arg,
                    "docker-archive",
                    str(image_path),
                ],
            )
            assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
            docker_image_open_mock.assert_called_once_with(image_path)
            docker_image.get_layer_scannables.assert_called_once_with(layer_info)

            if json_output:
                output = json.loads(result.output)
                assert len(output["entities_with_incidents"]) == 1
            else:
                assert "file_secret: 1 secret detected" in result.output
