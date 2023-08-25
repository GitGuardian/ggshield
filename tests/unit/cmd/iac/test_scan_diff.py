from pathlib import Path

from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import my_vcr


@my_vcr.use_cassette("test_iac_scan_diff_no_argument")
def test_scan_diff_no_arg(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository
    WHEN running the iac scan diff command with no argument
    THEN the return code is 0
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            ["iac", "scan", "diff", "--ref", "HEAD"],
        )
        assert result.exit_code == ExitCode.SUCCESS


@my_vcr.use_cassette("test_iac_scan_diff_valid_args")
def test_scan_diff_valid_args(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository and valid arguments to the iac scan diff command
    WHEN running the iac scan diff command with those arguments
    THEN the return code is 0
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "diff",
            "--ref",
            "HEAD",
            "--staged",
            "--minimum-severity",
            "MEDIUM",
            "--ignore-policy",
            "GG_IAC_0001",
            "--ignore-policy",
            "GG_IAC_0002",
            "--ignore-path",
            "**",
            str(tmp_path),
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS


def test_invalid_policy_id(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository and arguments to the iac scan diff command with non-correct policy id to ignore
    WHEN running the iac scan diff command with those arguments
    THEN the return code is 1
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "diff",
            "--ref",
            "HEAD",
            "--ignore-policy",
            "GG_IAC_0001",
            "--ignore-policy",
            "GG_IAC_002",
            str(tmp_path),
        ],
    )
    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert (
        "The policies ['GG_IAC_002'] do not match the pattern 'GG_IAC_[0-9]{4}'"
        in str(result.exception)
    )


def test_iac_scan_diff_file_error_response(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a file
    WHEN running the iac scan diff command with a single file as path parameter
    THEN an error is thrown
    """
    file_path = Path(tmp_path / "iac_file_single_vulnerability.tf")
    file_path.write_text(_IAC_SINGLE_VULNERABILITY)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "diff",
            "--ref",
            "HEAD",
            str(file_path),
        ],
    )
    assert result.exit_code == ExitCode.USAGE_ERROR
    assert "Error: Invalid value for '[DIRECTORY]'" in result.stdout


def test_iac_scan_diff_no_ref_arg(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository
    WHEN running the iac scan diff command with no ref argument
    THEN the return code is 2
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "diff",
            ],
        )
        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "Error: Missing option '--ref'" in result.stdout


def test_iac_scan_diff_invalid_reference(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository
    WHEN running the iac scan diff command with an invalid git reference
    THEN the return code is 1
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    with cd(str(tmp_path)):
        result1 = cli_fs_runner.invoke(
            cli,
            ["iac", "scan", "diff", "--ref", "invalid_ref"],
        )
        assert result1.exit_code == ExitCode.USAGE_ERROR
        assert "Not a git reference" in result1.stdout
