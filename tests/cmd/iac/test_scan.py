from click.testing import CliRunner

from ggshield.cmd.main import cli


class TestScanIac:
    def test_scan_valid_args(self, cli_fs_runner: CliRunner) -> None:
        """
        GIVEN valid arguments to the iac scan command
        WHEN running the iac scan command with those arguments
        THEN the return code is 0
        """
        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "--level",
                "MEDIUM",
                "--ignore-policy",
                "GG_IAC_0001",
                "--ignore-policy",
                "GG_IAC_0002",
                "--ignore-path",
                ".",
                ".",
            ],
        )
        assert result.exit_code == 0

    def test_invalid_policy_id(self, cli_fs_runner: CliRunner) -> None:
        """
        GIVEN arguments to the iac scan command with non-correct policy id to ignore
        WHEN running the iac scan command with those arguments
        THEN the return code is 1
        """
        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "--ignore-policy",
                "GG_IAC_0001",
                "--ignore-policy",
                "GG_IAC_002",
                ".",
            ],
        )
        assert result.exit_code == 1
        assert (
            "The policies ['GG_IAC_002'] do not match the pattern 'GG_IAC_[0-9]{4}'"
            in str(result.exception)
        )
