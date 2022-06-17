import json
from pathlib import Path

from click.testing import CliRunner

from ggshield.cmd.main import cli
from tests.conftest import _IAC_SINGLE_VULNERABILITY, my_vcr


class TestScanIac:
    @my_vcr.use_cassette("test_iac_scan_empty_directory")
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
                "--minimum-severity",
                "MEDIUM",
                "--ignore-policy",
                "GG_IAC_0001",
                "--ignore-policy",
                "GG_IAC_0002",
                "--ignore-path",
                "**",
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

    def test_iac_scan_file_error_response(self, cli_fs_runner: CliRunner) -> None:
        Path("tmp/").mkdir(exist_ok=True)
        Path("tmp/iac_file_single_vulnerability.tf").write_text(
            _IAC_SINGLE_VULNERABILITY
        )

        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "tmp/iac_file_single_vulnerability.tf",
            ],
        )
        assert result.exit_code == 2
        assert "Error: Invalid value for 'DIRECTORY'" in result.stdout

    @my_vcr.use_cassette("test_iac_scan_error_response")
    def test_iac_scan_error_response(self, cli_fs_runner: CliRunner) -> None:
        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                ".",
            ],
        )
        assert "Error scanning. Results may be incomplete." in result.stdout
        assert "404:Not found (404)" in result.stdout

    @my_vcr.use_cassette("test_iac_scan_error_response")
    def test_iac_scan_json_error_response(self, cli_fs_runner: CliRunner) -> None:
        cli_fs_runner.mix_stderr = False
        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "--json",
                ".",
            ],
        )
        assert "Error scanning. Results may be incomplete." in result.stderr
        assert "404:Not found (404)" in result.stderr
        assert json.loads(result.stdout) == {
            "entities_with_incidents": [],
            "iac_engine_version": "",
            "id": ".",
            "total_incidents": 0,
            "type": "path_scan",
        }
