import json
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.cmd.main import cli
from ggshield.core.errors import ExitCode
from ggshield.scan import Files, ScanCollection, StringScannable
from ggshield.scan.docker import LayerInfo, _validate_filepath
from tests.unit.conftest import (
    DATA_PATH,
    UNCHECKED_SECRET_PATCH,
    assert_invoke_exited_with,
    assert_invoke_ok,
    my_vcr,
)


DOCKER_EXAMPLE_PATH = DATA_PATH / "docker-example.tar.xz"
DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH = (
    DATA_PATH / "docker-incomplete-manifest-example.tar.xz"
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
        scan_mock.return_value = ScanCollection(
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
        scan_mock.return_value = ScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "docker", "ggshield-non-existant"],
        )
        assert_invoke_ok(result)
        assert result.output == ""

    @patch("ggshield.cmd.secret.scan.docker.docker_save_to_tmp")
    @patch("ggshield.cmd.secret.scan.docker.docker_scan_archive")
    def test_docker_scan_failed_to_save(
        self, scan_mock: Mock, save_mock: Mock, cli_fs_runner: click.testing.CliRunner
    ):
        save_mock.side_effect = click.UsageError(
            'Image "ggshield-non-existant" not found'
        )
        scan_mock.return_value = ScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "docker", "ggshield-non-existant"],
        )
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert 'Image "ggshield-non-existant" not found' in result.output

    @patch("ggshield.scan.docker._get_config")
    @patch("ggshield.scan.docker.DockerImage.get_layers")
    @pytest.mark.parametrize(
        "image_path", [DOCKER_EXAMPLE_PATH, DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH]
    )
    @pytest.mark.parametrize("json_output", (False, True))
    def test_docker_scan_archive(
        self,
        get_layers_mock: Mock,
        _get_config_mock: Mock,
        cli_fs_runner: click.testing.CliRunner,
        image_path: Path,
        json_output: bool,
    ):
        assert image_path.exists()

        layer_info = LayerInfo(filename="12345678/layer.tar", command="COPY foo")
        scannable = StringScannable(content=UNCHECKED_SECRET_PATCH, url="file_secret")

        def get_layers():
            yield (layer_info, Files([scannable]))

        get_layers_mock.side_effect = get_layers

        _get_config_mock.return_value = (
            None,
            None,
            StringScannable(content="", url="Dockerfile or build-args"),
        )
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
            _get_config_mock.assert_called_once()
            get_layers_mock.assert_called_once()

            if json_output:
                output = json.loads(result.output)
                assert len(output["entities_with_incidents"]) == 1
            else:
                assert "file_secret: 1 incident detected" in result.output
