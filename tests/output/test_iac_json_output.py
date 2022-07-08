import json
from pathlib import Path
from typing import Any, Dict

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
            "--json",
            "tmp",
        ],
    )

    json_result = load_json(result)
    assert_iac_version_displayed(json_result, 1)
    assert_file_single_vulnerability_displayed(json_result)


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
            "--json",
            "tmp",
        ],
    )

    json_result = load_json(result)
    assert_iac_version_displayed(json_result, 2)
    assert_file_multiple_vulnerabilities_displayed(json_result)


@my_vcr.use_cassette("test_iac_scan_no_vulnerabilities")
def test_display_no_vulnerability(cli_fs_runner: CliRunner):
    Path("tmp/").mkdir(exist_ok=True)
    Path("tmp/iac_file_no_vulnerabilities.tf").write_text(_IAC_NO_VULNERABILITIES)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "--json",
            "tmp",
        ],
    )

    json_result = load_json(result)
    assert_iac_version_displayed(json_result, 0)
    assert len(json_result["entities_with_incidents"]) == 0


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
            "--json",
            "tmp",
        ],
    )

    json_result = load_json(result)
    assert_iac_version_displayed(json_result, 3)
    assert_file_single_vulnerability_displayed(json_result)
    assert_file_multiple_vulnerabilities_displayed(json_result)


def load_json(result: Result) -> Dict[str, Any]:
    return json.loads(result.stdout)


def assert_iac_version_displayed(json_result: Dict[str, Any], total_incidents: int):
    assert json_result["iac_engine_version"] == "1.1.0"
    assert json_result["type"] == "path_scan"
    assert json_result["id"] == ""
    assert json_result["total_incidents"] == total_incidents


def assert_file_single_vulnerability_displayed(json_result: Dict[str, Any]):
    file_result = [
        file_result
        for file_result in json_result["entities_with_incidents"]
        if file_result["filename"] == "iac_file_single_vulnerability.tf"
    ]
    assert len(file_result) == 1
    assert file_result[0] == {
        "filename": "iac_file_single_vulnerability.tf",
        "incidents": [
            {
                "policy": "Plain HTTP is used",
                "policy_id": "GG_IAC_0001",
                "line_end": 3,
                "line_start": 3,
                "description": "Plain HTTP should not be used, it is unencrypted. HTTPS should be used instead.",
                "documentation_url": "https://gitguardian.com",
                "component": "aws_alb_listener.bad_example",
                "severity": "HIGH",
            }
        ],
        "total_incidents": 1,
    }


def assert_file_multiple_vulnerabilities_displayed(json_result: Dict[str, Any]):
    file_result = [
        file_result
        for file_result in json_result["entities_with_incidents"]
        if file_result["filename"] == "iac_file_multiple_vulnerabilities.tf"
    ]
    assert len(file_result) == 1
    assert file_result[0] == {
        "filename": "iac_file_multiple_vulnerabilities.tf",
        "incidents": [
            {
                "policy": "Unrestricted egress traffic might lead to remote code execution.",
                "policy_id": "GG_IAC_0002",
                "line_end": 4,
                "line_start": 4,
                "description": "Open egress means that the asset can download data from the whole web.",
                "documentation_url": "https://gitguardian.com",
                "component": "aws_security_group.bad_example",
                "severity": "HIGH",
            },
            {
                "policy": "Unrestricted ingress traffic leaves assets exposed to remote attacks.",
                "policy_id": "GG_IAC_0003",
                "line_end": 10,
                "line_start": 10,
                "description": "A security group has open ingress from all IPs, and on all ports. This means that the\nassets in this security group are exposed to the whole web.\n\nFurthermore, no port range is specified. This\nmeans that some applications running on assets of this security group may be reached by\nexternal traffic, while they are not expected to do so.",  # noqa: E501
                "documentation_url": "https://gitguardian.com",
                "component": "aws_security_group_rule.bad_example",
                "severity": "HIGH",
            },
        ],
        "total_incidents": 2,
    }
