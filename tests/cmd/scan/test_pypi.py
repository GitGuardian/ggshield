import re
import subprocess
import sys
from pathlib import Path
from typing import Set
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.cmd.secret.scan.pypi import (
    PYPI_DOWNLOAD_TIMEOUT,
    get_files_from_package,
    save_package_to_tmp,
)


class TestPipDownload:
    package_name: str = "what-ever-non-existing"
    tmp_dir: str = "/tmp/iam-temporary"

    def test_pip_download_success(self):
        with patch("subprocess.run") as call:
            save_package_to_tmp(temp_dir=self.tmp_dir, package_name=self.package_name)

            call.assert_called_once_with(
                [
                    "pip",
                    "download",
                    self.package_name,
                    "--dest",
                    self.tmp_dir,
                    "--no-deps",
                ],
                check=True,
                stdout=sys.stderr,
                stderr=sys.stderr,
                timeout=PYPI_DOWNLOAD_TIMEOUT,
            )

    def test_pip_download_nonexistent_package(self):
        with patch(
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, cmd=None)
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match=f'Failed to download "{self.package_name}"',
            ):
                save_package_to_tmp(
                    temp_dir=self.tmp_dir, package_name=self.package_name
                )

    def test_pip_download_timeout(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd=None, timeout=PYPI_DOWNLOAD_TIMEOUT
            ),
        ):
            with pytest.raises(
                click.exceptions.ClickException,
                match=(
                    f'Command "pip download {self.package_name} '
                    f'--dest {self.tmp_dir} --no-deps" timed out'
                ),
            ):
                save_package_to_tmp(
                    temp_dir=self.tmp_dir, package_name=self.package_name
                )


class TestListPackageFiles:
    package_name: str = "what-ever-non-existing"
    tmp_dir: str = "/tmp/iam-temporary"
    exclusion_regexes: Set[re.Pattern] = set([re.compile("i am a regex")])

    @pytest.mark.parametrize(
        "extension,verbose",
        [
            ("whl", True),
            ("whl", False),
            ("tar.gz", True),
        ],
    )
    @patch("ggshield.cmd.secret.scan.pypi.get_files_from_paths")
    @patch("shutil.unpack_archive")
    def test_unpack_archive_format(
        self,
        unpack_archive_mock: Mock,
        get_files_from_paths_mock: Mock,
        extension: str,
        verbose: bool,
    ):
        archive_path: str = Path(f"{self.tmp_dir}/{self.package_name}.{extension}")

        with patch.object(Path, "iterdir", return_value=iter([archive_path])):
            get_files_from_package(
                archive_dir=self.tmp_dir,
                package_name=self.package_name,
                exclusion_regexes=self.exclusion_regexes,
                verbose=verbose,
            )

            unpack_kwargs = {"format": "zip"} if extension == "whl" else {}
            unpack_archive_mock.assert_called_once_with(
                str(archive_path),
                extract_dir=Path(self.tmp_dir),
                **unpack_kwargs,
            )

            expected_exclusion_regexes = self.exclusion_regexes
            expected_exclusion_regexes.add(
                re.compile(f"{self.package_name}.{extension}")
            )

            get_files_from_paths_mock.assert_called_once_with(
                paths=[self.tmp_dir],
                exclusion_regexes=expected_exclusion_regexes,
                recursive=True,
                yes=True,
                verbose=verbose,
                ignore_git=True,
            )
