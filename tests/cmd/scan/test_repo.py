from ggshield.cmd.main import cli
from tests.conftest import assert_invoke_exited_with


class TestScanRepo:
    def test_invalid_scan_repo_github(self, cli_fs_runner):
        """
        GIVEN a repo url from github that doesn't finish in .git
        WHEN scan repo is called
        THEN a validation error proposing error correction should be shown
        """
        result = cli_fs_runner.invoke(
            cli, ["scan", "repo", "https://github.com/gitguardian/ggshield"]
        )
        assert_invoke_exited_with(result, 1)
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
            cli, ["scan", "repo", "trial.gitguardian.com/gitguardian/ggshield"]
        )
        assert_invoke_exited_with(result, 1)
        assert (
            "Error: trial.gitguardian.com/gitguardian/ggshield is"
            " neither a valid path nor a git URL" in result.output
        )
