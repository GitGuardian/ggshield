from pathlib import Path
from typing import Union

from ggshield.core.scan.scan_context import ScanContext
from ggshield.core.scan.scan_mode import ScanMode
from tests.repository import Repository


class TestScanContextRepositoryURL:
    def _assert_repo_url_in_headers(
        self, context: ScanContext, expected_url: Union[Path, str]
    ):
        assert context.get_http_headers().get("GGShield-Repository-URL") == str(
            expected_url
        )

    def _assert_no_repo_url_in_headers(self, context: ScanContext):
        assert context.get_http_headers().get("GGShield-Repository-URL") is None

    def test_scan_context_no_repo(
        self,
        tmp_path: Path,
    ):
        """
        GIVEN a directory which is not a git repo
        WHEN passing the local path to the scan context
        THEN there is no GGShield-Repository-URL in the headers
        """
        context = ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="ggshield secret scan path",
            target_path=tmp_path,
        )
        self._assert_no_repo_url_in_headers(context)

    def test_scan_context_repository_url_parsed(self, tmp_path: Path):
        """
        GIVEN a repository with a remote (url)
        WHEN passing the local path to the scan context
        THEN the remote url is found and simplified
        """
        local_repo = Repository.create(tmp_path)
        remote_url = "https://user:password@github.com:84/owner/repository.git"
        expected_url = "github.com/owner/repository"
        local_repo.git("remote", "add", "origin", remote_url)

        context = ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="ggshield secret scan path",
            target_path=local_repo.path,
        )
        self._assert_repo_url_in_headers(context, expected_url)
