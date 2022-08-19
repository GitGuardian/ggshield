import re
from pathlib import Path

from click.testing import CliRunner, Result

from ggshield.cmd.main import cli
from tests.conftest import (
    _IAC_MULTIPLE_VULNERABILITIES,
    _IAC_NO_VULNERABILITIES,
    _IAC_SINGLE_VULNERABILITY,
    assert_invoke_exited_with,
    assert_invoke_ok,
    my_vcr,
)


@my_vcr.use_cassette("test_iac_scan_single_vulnerability")
def test_display_single_vulnerability(tmp_path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_single_vulnerability.tf").write_text(
        _IAC_SINGLE_VULNERABILITY
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            str(tmp_path),
        ],
    )
    assert_iac_version_displayed(result)
    assert_file_single_vulnerability_displayed(result)


@my_vcr.use_cassette("test_iac_scan_single_vulnerability")
def test_exit_zero_single_vulnerability(tmp_path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_single_vulnerability.tf").write_text(
        _IAC_SINGLE_VULNERABILITY
    )
    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "--exit-zero",
            str(tmp_path),
        ],
    )
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_iac_scan_multiple_vulnerabilities")
def test_display_multiple_vulnerabilities(tmp_path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_multiple_vulnerabilities.tf").write_text(
        _IAC_MULTIPLE_VULNERABILITIES
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            str(tmp_path),
        ],
    )

    assert_iac_version_displayed(result)
    assert_file_multiple_vulnerabilities_displayed(result)
    assert_no_failures_displayed(result)


@my_vcr.use_cassette("test_iac_scan_no_vulnerabilities")
def test_display_no_vulnerability(tmp_path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_no_vulnerabilities.tf").write_text(_IAC_NO_VULNERABILITIES)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            str(tmp_path),
        ],
    )

    assert_iac_version_displayed(result)
    assert "No incidents have been found" in result.stdout
    assert_no_failures_displayed(result)
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_iac_scan_multiple_files")
def test_display_multiple_files(cli_fs_runner: CliRunner):
    Path("tmp/").mkdir(exist_ok=True)
    Path("tmp/iac_file_single_vulnerability.tf").write_text(_IAC_SINGLE_VULNERABILITY)
    Path("tmp/iac_file_multiple_vulnerabilities.tf").write_text(
        _IAC_MULTIPLE_VULNERABILITIES
    )
    Path("tmp/iac_file_no_vulnerabilities.tf").write_text(_IAC_NO_VULNERABILITIES)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "tmp",
        ],
    )

    assert_iac_version_displayed(result)
    assert_file_single_vulnerability_displayed(result)
    assert_file_multiple_vulnerabilities_displayed(result)
    assert_no_failures_displayed(result)


def assert_iac_version_displayed(result: Result):
    assert re.search(r"iac-engine-version: \d\.\d{1,3}\.\d", result.stdout)


def assert_no_failures_displayed(result: Result):
    assert "Error scanning. Results may be incomplete." not in result.stdout


def assert_file_single_vulnerability_displayed(result: Result):
    assert (
        "1 incident has been found in file iac_file_single_vulnerability.tf"
        in result.stdout
    )
    assert set(re.findall(r"GG_IAC_\d{4}", result.stdout)) >= {
        "GG_IAC_0001",
    }
    assert '2 | resource "aws_alb_listener" "bad_example" {' in result.stdout
    assert_invoke_exited_with(result, 1)


def assert_file_multiple_vulnerabilities_displayed(result: Result):
    assert (
        "2 incidents have been found in file iac_file_multiple_vulnerabilities.tf"
        in result.stdout
    )
    assert set(re.findall(r"GG_IAC_\d{4}", result.stdout)) >= {
        "GG_IAC_0002",
        "GG_IAC_0003",
    }
    assert '2 | resource "aws_security_group" "bad_example" {' in result.stdout
    assert '8 |  resource "aws_security_group_rule" "bad_example" {' in result.stdout
    assert_invoke_exited_with(result, 1)
