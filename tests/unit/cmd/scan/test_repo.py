from unittest.mock import Mock, patch

from pygitguardian.models import Detail

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

    @patch(
        "pygitguardian.client.GGClient.read_metadata",
        return_value=Detail("Service is unavailable", 503),
    )
    def test_server_unavailable(self, _: Mock, cli_fs_runner):
        """
        GIVEN a server that is unavailable
        WHEN scan repo is called
        THEN it should return 0
        """
        result = cli_fs_runner.invoke(
            cli,
            ["secret", "scan", "repo", "https://github.com/gitguardian/ggshield.git"],
        )
        assert_invoke_exited_with(result, ExitCode.GITGUARDIAN_SERVER_UNAVAILABLE)
        assert "GitGuardian server is not responding" in result.output

    @patch("ggshield.cmd.secret.scan.repo.scan_repo_path", return_value=0)
    @patch("ggshield.cmd.secret.scan.repo.git")
    def test_clone_passes_url_after_end_of_options(
        self, git_mock: Mock, _: Mock, cli_fs_runner
    ):
        """
        GIVEN a git URL
        WHEN scan repo is called
        THEN `git clone` receives the URL after --end-of-options
        """
        url = "https://github.com/gitguardian/ggshield.git"
        cli_fs_runner.invoke(cli, ["secret", "scan", "repo", url])

        cmd = git_mock.call_args.args[0]
        assert cmd[:4] == ["clone", "--mirror", "--end-of-options", url]
