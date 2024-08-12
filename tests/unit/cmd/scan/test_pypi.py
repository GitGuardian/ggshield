import re
import subprocess
import sys
from pathlib import Path
from typing import Pattern, Set
from unittest.mock import Mock, patch

import pytest

from ggshield.cmd.secret.scan.pypi import (
    PYPI_DOWNLOAD_TIMEOUT,
    get_files_from_package,
    save_package_to_tmp,
)
from ggshield.core.errors import UnexpectedError
from ggshield.utils.files import ListFilesMode


class TestPipDownload:
    package_name: str = "what-ever-non-existing"

    def test_pip_download_success(self, tmp_path):
        with patch("subprocess.run") as call:
            save_package_to_tmp(temp_dir=tmp_path, package_name=self.package_name)

            call.assert_called_once_with(
                [
                    "pip",
                    "download",
                    self.package_name,
                    "--dest",
                    str(tmp_path),
                    "--no-deps",
                ],
                check=True,
                stdout=sys.stderr,
                stderr=sys.stderr,
                timeout=PYPI_DOWNLOAD_TIMEOUT,
            )

    def test_pip_download_nonexistent_package(self, tmp_path):
        with patch(
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, cmd=None)
        ):
            with pytest.raises(
                UnexpectedError,
                match=f'Failed to download "{self.package_name}"',
            ):
                save_package_to_tmp(temp_dir=tmp_path, package_name=self.package_name)

    def test_pip_download_timeout(self, tmp_path):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd=None, timeout=PYPI_DOWNLOAD_TIMEOUT
            ),
        ):
            with pytest.raises(
                UnexpectedError,
                match=(
                    f'Command "pip download {self.package_name} '
                    f'--dest {re.escape(str(tmp_path))} --no-deps" timed out'
                ),
            ):
                save_package_to_tmp(temp_dir=tmp_path, package_name=self.package_name)


class TestListPackageFiles:
    package_name: str = "what-ever-non-existing"
    exclusion_regexes: Set[Pattern[str]] = {re.compile("i am a regex")}

    @pytest.mark.parametrize("extension", ["whl", "tar.gz"])
    @patch("ggshield.cmd.secret.scan.pypi.create_files_from_paths")
    @patch("ggshield.cmd.secret.scan.pypi.safe_unpack")
    def test_unpack_archive_format(
        self,
        safe_unpack_mock: Mock,
        create_files_from_paths_mock: Mock,
        extension: str,
        tmp_path,
    ):
        # TODO: rewrite this test: it tests implementation details instead of the
        # function outcome
        archive_path = tmp_path / f"{self.package_name}.{extension}"
        create_files_from_paths_mock.return_value = ([], [])

        with patch.object(Path, "iterdir", return_value=iter([archive_path])):
            get_files_from_package(
                archive_dir=tmp_path,
                package_name=self.package_name,
                exclusion_regexes=self.exclusion_regexes,
            )

            safe_unpack_mock.assert_called_once_with(
                archive_path,
                extract_dir=tmp_path,
            )

            expected_exclusion_regexes = self.exclusion_regexes
            expected_exclusion_regexes.add(
                re.compile(f"{self.package_name}.{extension}")
            )

            create_files_from_paths_mock.assert_called_once_with(
                paths=[tmp_path],
                exclusion_regexes=expected_exclusion_regexes,
                list_files_mode=ListFilesMode.ALL,
            )
