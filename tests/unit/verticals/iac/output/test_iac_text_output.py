import datetime
import re
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner, Result
from pygitguardian.iac_models import IaCFileResult

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.verticals.iac.output.iac_text_output_handler import IaCTextOutputHandler
from tests.conftest import (
    IAC_MULTIPLE_VULNERABILITIES,
    IAC_NO_VULNERABILITIES,
    IAC_SINGLE_VULNERABILITY,
)
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok, my_vcr
from tests.unit.verticals.iac.utils import (
    generate_diff_scan_collection,
    generate_path_scan_collection,
    generate_vulnerability,
)


@my_vcr.use_cassette("test_iac_scan_single_vulnerability")
def test_display_single_vulnerability(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_single_vulnerability.tf").write_text(IAC_SINGLE_VULNERABILITY)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            str(tmp_path),
        ],
    )
    assert_beta_warning_displayed(result)
    assert_iac_version_displayed(result)
    assert_file_single_vulnerability_displayed(result)
    assert_documentation_url_displayed(result)


@my_vcr.use_cassette("test_iac_scan_single_vulnerability")
def test_exit_zero_single_vulnerability(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_single_vulnerability.tf").write_text(IAC_SINGLE_VULNERABILITY)
    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            "--exit-zero",
            str(tmp_path),
        ],
    )
    assert_beta_warning_displayed(result)
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_iac_scan_multiple_vulnerabilities")
def test_display_multiple_vulnerabilities(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_multiple_vulnerabilities.tf").write_text(
        IAC_MULTIPLE_VULNERABILITIES
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            str(tmp_path),
        ],
    )

    assert_beta_warning_displayed(result)
    assert_iac_version_displayed(result)
    assert_file_multiple_vulnerabilities_displayed(result)
    assert_no_failures_displayed(result)


@my_vcr.use_cassette("test_iac_scan_no_vulnerabilities")
def test_display_no_vulnerability(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_no_vulnerabilities.tf").write_text(IAC_NO_VULNERABILITIES)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            str(tmp_path),
        ],
    )

    assert_beta_warning_displayed(result)
    assert_iac_version_displayed(result)
    assert "No incidents have been found" in result.stdout
    assert_no_failures_displayed(result)
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_iac_scan_multiple_files")
def test_display_multiple_files(cli_fs_runner: CliRunner):
    Path("tmp/").mkdir(exist_ok=True)
    Path("tmp/iac_file_single_vulnerability.tf").write_text(IAC_SINGLE_VULNERABILITY)
    Path("tmp/iac_file_multiple_vulnerabilities.tf").write_text(
        IAC_MULTIPLE_VULNERABILITIES
    )
    Path("tmp/iac_file_no_vulnerabilities.tf").write_text(IAC_NO_VULNERABILITIES)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            "tmp",
        ],
    )

    assert_beta_warning_displayed(result)
    assert_iac_version_displayed(result)
    assert_file_single_vulnerability_displayed(result)
    assert_file_multiple_vulnerabilities_displayed(result)
    assert_no_failures_displayed(result)


@patch("ggshield.core.text_utils.format_text", lambda text, *args: text)
@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("scan_type", [ScanMode.DIRECTORY_ALL, ScanMode.DIRECTORY_DIFF])
def test_text_all_output_no_ignored(verbose: bool, scan_type: ScanMode, tmp_path: Path):
    """
    GIVEN   - a file result with ignored & unignored vulns
            - a file result with only unignored vulns
            - a file result with only ignored vulns
    WHEN    showing scan output
    THEN    ignored vulns are not shown
    """
    output_path = tmp_path / "output"

    collection_factory_fn = (
        generate_path_scan_collection
        if scan_type == ScanMode.DIRECTORY_ALL
        else generate_diff_scan_collection
    )
    collection = collection_factory_fn(
        [
            IaCFileResult(
                filename="iac_file_single_vulnerability.tf",
                incidents=[
                    generate_vulnerability(policy_id="GG_IAC_0001"),
                    generate_vulnerability(status="IGNORED", policy_id="GG_IAC_0002"),
                ],
            ),
            IaCFileResult(
                filename="iac_file_multiple_vulnerabilities.tf",
                incidents=[
                    generate_vulnerability(policy_id="GG_IAC_0003"),
                    generate_vulnerability(policy_id="GG_IAC_0004"),
                ],
            ),
            IaCFileResult(
                filename="iac_file_no_vulnerabilities.tf",
                incidents=[
                    generate_vulnerability(status="IGNORED", policy_id="GG_IAC_0005"),
                    generate_vulnerability(status="IGNORED", policy_id="GG_IAC_0006"),
                ],
            ),
        ]
    )

    output_handler = IaCTextOutputHandler(verbose=verbose, output=str(output_path))
    process_fn = (
        output_handler.process_scan
        if scan_type == ScanMode.DIRECTORY_ALL
        else output_handler.process_diff_scan
    )
    exit_code = process_fn(collection)

    assert exit_code == ExitCode.SCAN_FOUND_PROBLEMS

    output = output_path.read_text()
    assert "iac_file_single_vulnerability.tf: 1 " in output
    assert "iac_file_multiple_vulnerabilities.tf: 2 " in output
    assert "iac_file_no_vulnerabilities.tf" not in output
    assert set(re.findall(r"GG_IAC_\d{4}", output)) == {
        "GG_IAC_0001",
        "GG_IAC_0003",
        "GG_IAC_0004",
    }
    if scan_type == ScanMode.DIRECTORY_DIFF:
        assert "[+] 3 new incidents detected" in output


@patch("ggshield.core.text_utils.format_text", lambda text, *args: text)
@pytest.mark.parametrize("scan_type", [ScanMode.DIRECTORY_ALL, ScanMode.DIRECTORY_DIFF])
def test_text_all_output_previously_ignored(scan_type: ScanMode, tmp_path: Path):
    """
    GIVEN   - a vuln with ignored_until date in the past
    GIVEN   - a vuln with ignored_until date in the future
    GIVEN   - a vuln with no ignored_until date
    GIVEN   - a vuln which is not ignored
    WHEN    showing scan output
    THEN    previously ignored vulns are showed with the end of grace period date
            but ignored vulns are not shown
    """
    output_path = tmp_path / "output"

    current_time = datetime.datetime.now()
    past_time = current_time - datetime.timedelta(days=1)
    future_time = current_time + datetime.timedelta(days=1)

    collection_factory_fn = (
        generate_path_scan_collection
        if scan_type == ScanMode.DIRECTORY_ALL
        else generate_diff_scan_collection
    )
    collection = collection_factory_fn(
        [
            IaCFileResult(
                filename="iac_file.tf",
                incidents=[
                    generate_vulnerability(policy_id="GG_IAC_0001"),
                    generate_vulnerability(status="IGNORED", policy_id="GG_IAC_0002"),
                    generate_vulnerability(
                        ignored_until=past_time, policy_id="GG_IAC_0003"
                    ),
                    generate_vulnerability(
                        status="IGNORED",
                        ignored_until=future_time,
                        policy_id="GG_IAC_0004",
                    ),
                ],
            ),
        ]
    )

    output_handler = IaCTextOutputHandler(verbose=True, output=str(output_path))
    process_fn = (
        output_handler.process_scan
        if scan_type == ScanMode.DIRECTORY_ALL
        else output_handler.process_diff_scan
    )
    exit_code = process_fn(collection)

    assert exit_code == ExitCode.SCAN_FOUND_PROBLEMS

    with open(output_path, "r") as f:
        output = f.read()
        assert "iac_file.tf: 2 " in output
        assert set(re.findall(r"GG_IAC_\d{4}", output)) == {
            "GG_IAC_0001",
            "GG_IAC_0003",
        }
        assert (
            f"The incident is no longer ignored in the scan since {past_time.strftime('%Y-%m-%d')}"
            in output
        )
        if scan_type == ScanMode.DIRECTORY_DIFF:
            assert "[+] 2 new incidents detected" in output


def assert_beta_warning_displayed(result: Result):
    assert (
        "This feature is still in beta, its behavior may change in future versions."
        in result.stdout
    )


def assert_iac_version_displayed(result: Result):
    assert re.search(r"iac-engine-version: \d\.\d{1,3}\.\d", result.stdout)


def assert_no_failures_displayed(result: Result):
    assert "Error scanning. Results may be incomplete." not in result.stdout


def assert_documentation_url_displayed(result: Result):
    base_doc_url = "https://docs.gitguardian.com/iac-security/policies/"
    regex = r"\((GG_IAC_\d{4})\).+" + base_doc_url.replace(".", r"\.") + r"\1"
    assert re.search(
        regex,
        result.stdout,
        re.S,
    )


def assert_file_single_vulnerability_displayed(result: Result):
    assert "iac_file_single_vulnerability.tf: 1 incident detected" in result.stdout
    assert set(re.findall(r"GG_IAC_\d{4}", result.stdout)) >= {
        "GG_IAC_0001",
    }
    assert '2 | resource "aws_alb_listener" "bad_example" {' in result.stdout
    assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)


def assert_file_multiple_vulnerabilities_displayed(result: Result):
    assert "iac_file_multiple_vulnerabilities.tf: 2 incidents detected" in result.stdout
    assert set(re.findall(r"GG_IAC_\d{4}", result.stdout)) >= {
        "GG_IAC_0002",
        "GG_IAC_0003",
    }
    assert '2 | resource "aws_security_group" "bad_example" {' in result.stdout
    assert '8 |  resource "aws_security_group_rule" "bad_example" {' in result.stdout
    assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
