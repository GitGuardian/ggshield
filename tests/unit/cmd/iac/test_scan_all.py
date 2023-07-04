import json
from pathlib import Path

import requests
from click.testing import CliRunner
from pytest_mock import MockerFixture

from ggshield.cmd.main import cli
from ggshield.core.errors import ExitCode
from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import my_vcr
from tests.unit.request_mock import create_json_response


def _setup_single_iac_vuln_repo() -> str:
    """
    Sets up a local repo with a single vulnerable IaC file.
    :returns: a string representing the path to the file

    """
    tmp_path = Path(".")

    repo = Repository.create(tmp_path)

    iac_file_name = "iac_file_single_vulnerability.tf"

    tracked_file = tmp_path / iac_file_name
    tracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    repo.create_commit()
    return str(tracked_file)


@my_vcr.use_cassette("test_iac_scan_no_argument")
def test_scan_all_no_arg(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the iac scan command with no argument
    THEN the return code is 0
    """
    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS


@my_vcr.use_cassette("test_iac_scan_empty_directory")
def test_scan_all_valid_args(cli_fs_runner: CliRunner) -> None:
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
            "all",
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
    assert result.exit_code == ExitCode.SUCCESS


def test_invalid_policy_id(cli_fs_runner: CliRunner) -> None:
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
            "all",
            "--ignore-policy",
            "GG_IAC_0001",
            "--ignore-policy",
            "GG_IAC_002",
            ".",
        ],
    )
    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert (
        "The policies ['GG_IAC_002'] do not match the pattern 'GG_IAC_[0-9]{4}'"
        in str(result.exception)
    )


def test_iac_scan_all_file_error_response(cli_fs_runner: CliRunner) -> None:
    with cli_fs_runner.isolated_filesystem():
        iac_file_path = _setup_single_iac_vuln_repo()

        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "all",
                iac_file_path,
            ],
        )
    assert result.exit_code == ExitCode.USAGE_ERROR
    assert "Error: Invalid value for '[DIRECTORY]'" in result.stdout


def test_iac_scan_all_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )
    with cli_fs_runner.isolated_filesystem():
        _setup_single_iac_vuln_repo()

        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "all",
                ".",
            ],
        )
    assert "Error scanning." in result.stdout
    assert "The following chunk is affected" not in result.stdout
    assert "404:Not found (404)" in result.stdout


def test_iac_scan_all_json_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )
    cli_fs_runner.mix_stderr = False
    with cli_fs_runner.isolated_filesystem():

        _setup_single_iac_vuln_repo()

        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "all",
                "--json",
                ".",
            ],
        )
    assert "Error scanning." in result.stderr
    assert "404:Not found (404)" in result.stderr
    assert json.loads(result.stdout) == {
        "entities_with_incidents": [],
        "iac_engine_version": "",
        "id": ".",
        "total_incidents": 0,
        "type": "path_scan",
    }


def test_iac_scan_all_unknown_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )

    with cli_fs_runner.isolated_filesystem():

        _setup_single_iac_vuln_repo()

        result = cli_fs_runner.invoke(
            cli,
            ["iac", "scan", "all", "."],
        )
    assert "Error scanning." in result.stdout
    assert "404:Not found (404)" in result.stdout


def test_iac_scan_all_error_response_read_timeout(
    cli_fs_runner: CliRunner, mocker: MockerFixture
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        side_effect=requests.exceptions.ReadTimeout("Timeout error"),
    )
    with cli_fs_runner.isolated_filesystem():
        _setup_single_iac_vuln_repo()

        result = cli_fs_runner.invoke(
            cli,
            ["iac", "scan", "all", "."],
        )
    assert "Error scanning." in result.stdout
    assert "504:The request timed out." in result.stdout
