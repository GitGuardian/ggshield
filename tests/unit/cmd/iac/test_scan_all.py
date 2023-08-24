import json
from pathlib import Path

import pytest
import requests
from click.testing import CliRunner
from pytest_mock import MockerFixture

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import my_vcr
from tests.unit.request_mock import create_json_response


# `iac scan` is set for deprecation, but should behave exactly as `iac scan all` in the meantime
pytestmark = pytest.mark.parametrize(
    "cli_command", [["iac", "scan", "all"], ["iac", "scan"]]
)


def setup_single_iac_vuln_repo(tmp_path: Path) -> str:
    """
    Sets up a local repo with a single vulnerable IaC file from a given tmp_path.
    :returns: a string representing the path to the file
    """

    repo = Repository.create(tmp_path)

    iac_file_name = "iac_file_single_vulnerability.tf"

    tracked_file = tmp_path / iac_file_name
    tracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    repo.create_commit()
    return str(tracked_file)


@my_vcr.use_cassette("test_iac_scan_no_argument")
def test_scan_all_no_arg(cli_fs_runner: CliRunner, cli_command) -> None:
    """
    GIVEN -
    WHEN running the iac scan command with no argument
    THEN the return code is 0
    """
    result = cli_fs_runner.invoke(
        cli,
        cli_command,
    )
    assert result.exit_code == ExitCode.SUCCESS


@my_vcr.use_cassette("test_iac_scan_empty_directory")
def test_scan_all_valid_args(cli_fs_runner: CliRunner, cli_command) -> None:
    """
    GIVEN valid arguments to the iac scan command
    WHEN running the iac scan command with those arguments
    THEN the return code is 0
    """
    result = cli_fs_runner.invoke(
        cli,
        cli_command
        + [
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


def test_invalid_policy_id(cli_fs_runner: CliRunner, cli_command) -> None:
    """
    GIVEN arguments to the iac scan command with non-correct policy id to ignore
    WHEN running the iac scan command with those arguments
    THEN the return code is 1
    """
    result = cli_fs_runner.invoke(
        cli,
        cli_command
        + [
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


def test_iac_scan_all_file_error_response(
    cli_fs_runner: CliRunner, cli_command
) -> None:
    with cli_fs_runner.isolated_filesystem():
        iac_file_path = setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command
            + [
                iac_file_path,
            ],
        )
    assert result.exit_code == ExitCode.USAGE_ERROR
    assert "Error: Invalid value for '[DIRECTORY]'" in result.stdout


def test_iac_scan_all_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )
    with cli_fs_runner.isolated_filesystem():
        setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command
            + [
                ".",
            ],
        )
    assert "Error scanning." in result.stdout
    assert "The following chunk is affected" not in result.stdout
    assert "404:Not found (404)" in result.stdout


def test_iac_scan_all_json_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )
    cli_fs_runner.mix_stderr = False
    with cli_fs_runner.isolated_filesystem():

        setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command
            + [
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
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )

    with cli_fs_runner.isolated_filesystem():

        setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command + ["."],
        )
    assert "Error scanning." in result.stdout
    assert "404:Not found (404)" in result.stdout


def test_iac_scan_all_error_response_read_timeout(
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        side_effect=requests.exceptions.ReadTimeout("Timeout error"),
    )
    with cli_fs_runner.isolated_filesystem():
        setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command + ["."],
        )
    assert "Error scanning." in result.stdout
    assert "504:The request timed out." in result.stdout


def test_iac_scan_all_verbose(cli_fs_runner: CliRunner, cli_command) -> None:
    with cli_fs_runner.isolated_filesystem():
        # GIVEN a repository with one IaC file and one non-IaC file
        path = Path(".")
        repo = Repository.create(path)

        iac_file_name = "iac_file.tf"
        non_iac_file_name = "non_iac_file.txt"

        tracked_iac_file = path / iac_file_name
        tracked_iac_file.write_text(_IAC_SINGLE_VULNERABILITY)
        repo.add(tracked_iac_file)

        tracked_non_iac_file = path / non_iac_file_name
        tracked_non_iac_file.write_text(_IAC_SINGLE_VULNERABILITY)
        repo.add(tracked_non_iac_file)

        repo.create_commit()

        # WHEN performing a scan all with the verbose option
        result = cli_fs_runner.invoke(
            cli,
            cli_command + [str(path), "-v"],
        )

        # THEN the IaC file appears in the output
        assert iac_file_name in result.stdout
        # AND the non-IaC file does not
        assert non_iac_file_name not in result.stdout
