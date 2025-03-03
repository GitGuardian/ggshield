from unittest.mock import Mock, patch

from requests import Response

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with


class TestScanRepo:
    def test_invalid_scan_repo_github(self, cli_fs_runner):
        """
        GIVEN a repo url from github that doesn't finish in .git
        WHEN scan repo is called
        THEN a validation error proposing error correction should be shown
        """
        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "repo", "https://github.com/gitguardian/ggshield"]
        )
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert (
            "Error: https://github.com/gitguardian/ggshield doesn't seem to "
            "be a valid git URL.\nDid you mean "
            "https://github.com/gitguardian/ggshield.git?" in result.output
        )

    def test_invalid_scan_repo_url(self, cli_fs_runner):
        """
        GIVEN an invalid repo url from github without prefix
        WHEN scan repo is called
        THEN a validation error should be shown
        """
        result = cli_fs_runner.invoke(
            cli,
            ["secret", "scan", "repo", "trial.gitguardian.com/gitguardian/ggshield"],
        )
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert (
            "Error: trial.gitguardian.com/gitguardian/ggshield is"
            " neither a valid path nor a git URL" in result.output
        )

    @patch("pygitguardian.client.GGClient.read_metadata")
    def test_server_unavailable(
        self,
        read_metadata_mock: Mock,
        cli_fs_runner,
    ):
        """
        GIVEN a server that is unavailable
        WHEN scan repo is called
        THEN it should return 0
        """

        # Set up the mock to return a 503 response
        response = Response()
        response.status_code = 503
        response.detail = "Service Temporarily Unavailable"
        read_metadata_mock.return_value = response

        result = cli_fs_runner.invoke(
            cli,
            ["secret", "scan", "repo", "https://github.com/gitguardian/ggshield.git"],
        )
        assert "Server is not responding" in result.output
        assert_invoke_exited_with(result, ExitCode.SERVER_UNAVAILABLE)
