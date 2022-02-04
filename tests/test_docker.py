import re
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.cmd import cli
from ggshield.docker import docker_pull_image, docker_save_to_tmp
from ggshield.scan.scannable import File, Files, ScanCollection

from .conftest import _SIMPLE_SECRET, my_vcr


DOCKER_EXAMPLE_PATH = Path(__file__).parent / "data" / "docker-example.tar.xz"
DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH = (
    Path(__file__).parent / "data" / "docker-incomplete-manifest-example.tar.xz"
)

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
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, cmd=None)
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match='Image "ggshield-non-existant" not found',
            ):
                docker_pull_image("ggshield-non-existant", DOCKER_TIMEOUT)

    def test_docker_pull_image_timeout(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=None, timeout=DOCKER_TIMEOUT),
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

    def test_docker_save_image_non_exist(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(
                1, cmd=None, stderr="reference does not exist".encode("utf-8")
            ),
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match='Image "ggshield-non-existant" not found',
            ):
                docker_save_to_tmp(
                    "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
                )

    def test_docker_save_image_timeout(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=None, timeout=DOCKER_TIMEOUT),
        ):
            expected_msg = f'Command "docker save ggshield-non-existant -o {str(self.TMP_ARCHIVE)}" timed out'  # noqa: E501
            with pytest.raises(
                click.exceptions.ClickException,
                match=re.escape(expected_msg),
            ):
                docker_save_to_tmp(
                    "ggshield-non-existant", self.TMP_ARCHIVE, DOCKER_TIMEOUT
                )


class TestDockerCMD:
    @patch("ggshield.docker.docker_save_to_tmp")
    @patch("ggshield.docker.docker_scan_archive")
    def test_docker_scan(
        self, scan_mock: Mock, save_mock, cli_fs_runner: click.testing.CliRunner
    ):
        scan_mock.return_value = ScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "scan", "docker", "ggshield-non-existant"],
        )
        assert result.exit_code == 0

    @patch("ggshield.docker.docker_save_to_tmp")
    @patch("ggshield.docker.docker_scan_archive")
    def test_docker_scan_abort(
        self, scan_mock: Mock, save_mock: Mock, cli_fs_runner: click.testing.CliRunner
    ):
        save_mock.side_effect = click.exceptions.Abort()
        scan_mock.return_value = ScanCollection(
            id="ggshield-non-existant", type="docker", results=[]
        )
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "scan", "docker", "ggshield-non-existant"],
        )
        assert result.output == ""
        assert result.exit_code == 0

    @patch("ggshield.docker.docker_save_to_tmp")
    @patch("ggshield.docker.docker_scan_archive")
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
            ["-v", "scan", "docker", "ggshield-non-existant"],
        )
        assert 'Error: Image "ggshield-non-existant" not found\n' in result.output
        assert result.exit_code == 1

    @patch("ggshield.docker.get_files_from_docker_archive")
    @pytest.mark.parametrize(
        "image_path", [DOCKER_EXAMPLE_PATH, DOCKER__INCOMPLETE_MANIFEST_EXAMPLE_PATH]
    )
    def test_docker_scan_archive(
        self,
        get_files_mock: Mock,
        cli_fs_runner: click.testing.CliRunner,
        image_path: Path,
    ):
        get_files_mock.return_value = Files(
            files=[File(document=_SIMPLE_SECRET, filename="file_secret")]
        )
        with my_vcr.use_cassette("test_scan_file_secret"):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "-v",
                    "scan",
                    "docker-archive",
                    str(image_path),
                ],
            )
            get_files_mock.assert_called_once()
            assert "1 incident has been found in file file_secret" in result.output
            assert result.exit_code == 1
