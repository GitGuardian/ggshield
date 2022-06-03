import json
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.cmd.main import cli
from ggshield.scan.scannable import File, Files, ScanCollection
from tests.conftest import _SIMPLE_SECRET, DATA_PATH, my_vcr


DOCKER_EXAMPLE_PATH = DATA_PATH / "docker-example.tar.xz"
DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH = (
    DATA_PATH / "docker-incomplete-manifest-example.tar.xz"
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
        assert result.exit_code == 0, result.output

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
        assert result.exit_code == 0, result.output
        assert result.output == ""

    @patch("ggshield.cmd.secret.scan.docker.docker_save_to_tmp")
    @patch("ggshield.cmd.secret.scan.docker.docker_scan_archive")
    def test_docker_scan_failed_to_save(
        self, scan_mock: Mock, save_mock: Mock, cli_fs_runner: click.testing.CliRunner
    ):
        save_mock.side_effect = click.exceptions.ClickException(
            'Image "ggshield-non-existant" not found'
        )
        scan_mock.return_value = ScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "docker", "ggshield-non-existant"],
        )
        assert result.exit_code == 1, result.output
        assert 'Error: Image "ggshield-non-existant" not found\n' in result.output

    @patch("ggshield.scan.docker.get_files_from_docker_archive")
    @pytest.mark.parametrize(
        "image_path", [DOCKER_EXAMPLE_PATH, DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH]
    )
    @pytest.mark.parametrize("json_output", (False, True))
    def test_docker_scan_archive(
        self,
        get_files_mock: Mock,
        cli_fs_runner: click.testing.CliRunner,
        image_path: Path,
        json_output: bool,
    ):
        assert image_path.exists()

        get_files_mock.return_value = Files(
            files=[File(document=_SIMPLE_SECRET, filename="file_secret")]
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
            assert result.exit_code == 1, result.stderr
            get_files_mock.assert_called_once()

            if json_output:
                output = json.loads(result.output)
                assert len(output["entities_with_incidents"]) == 1
            else:
                assert "1 incident has been found in file file_secret" in result.output
