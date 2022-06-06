from pathlib import Path

from click.testing import CliRunner, Result

from ggshield.cmd.main import cli
from tests.conftest import (
    _IAC_MULTIPLE_VULNERABILITIES,
    _IAC_NO_VULNERABILITIES,
    _IAC_SINGLE_VULNERABILITY,
    my_vcr,
)


@my_vcr.use_cassette("test_iac_scan_single_vulnerability")
def test_display_single_vulnerabilities(cli_fs_runner: CliRunner):
    Path("tmp/").mkdir(exist_ok=True)
    Path("tmp/iac_file_single_vulnerability.tf").write_text(_IAC_SINGLE_VULNERABILITY)

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


@my_vcr.use_cassette("test_iac_scan_multiple_vulnerabilities")
def test_display_multiple_vulnerabilities(cli_fs_runner: CliRunner):
    Path("tmp/").mkdir(exist_ok=True)
    Path("tmp/iac_file_multiple_vulnerabilities.tf").write_text(
        _IAC_MULTIPLE_VULNERABILITIES
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "tmp",
        ],
    )

    assert_iac_version_displayed(result)
    assert_file_multiple_vulnerabilities_displayed(result)
    assert_no_failures_displayed(result)


@my_vcr.use_cassette("test_iac_scan_no_vulnerabilities")
def test_display_no_vulnerability(cli_fs_runner: CliRunner):
    Path("tmp/").mkdir(exist_ok=True)
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
    assert "No incidents have been found" in result.stdout
    assert_no_failures_displayed(result)


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
    assert "iac-engine-version: 1.1.0" in result.stdout


def assert_no_failures_displayed(result: Result):
    assert "Error scanning. Results may be incomplete." not in result.stdout


def assert_file_single_vulnerability_displayed(result: Result):
    assert (
        "1 incident has been found in file iac_file_single_vulnerability.tf"
        in result.stdout
    )
    assert (
        ">>> Incident 1 (IaC): aws_alb_listener.bad_example: Plain HTTP is used (Ignore with SHA: shasha)"  # noqa: E501
        in result.stdout
    )
    assert '2 | resource "aws_alb_listener" "bad_example" {' in result.stdout


def assert_file_multiple_vulnerabilities_displayed(result: Result):
    assert (
        "2 incidents have been found in file iac_file_multiple_vulnerabilities.tf"
        in result.stdout
    )
    assert (
        ">>> Incident 1 (IaC): aws_security_group.bad_example: Unrestricted egress traffic might lead to remote code execution. (Ignore with SHA: shasha)"  # noqa: E501
        in result.stdout
    )
    assert '2 | resource "aws_security_group" "bad_example" {' in result.stdout
    assert (
        ">>> Incident 2 (IaC): aws_security_group_rule.bad_example: Unrestricted ingress traffic leaves assets exposed to remote attacks. (Ignore with SHA: shasha)"  # noqa: E501
        in result.stdout
    )
    assert '8 |  resource "aws_security_group_rule" "bad_example" {' in result.stdout
