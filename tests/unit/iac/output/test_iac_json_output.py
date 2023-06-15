import json
import re
from pathlib import Path
from typing import Any, Dict

import voluptuous.validators as validators
from click.testing import CliRunner, Result
from pytest_voluptuous import S

from ggshield.cmd.main import cli
from tests.unit.conftest import (
    _IAC_MULTIPLE_VULNERABILITIES,
    _IAC_NO_VULNERABILITIES,
    _IAC_SINGLE_VULNERABILITY,
    my_vcr,
)
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.output import IaCJSONOutputHandler
from ggshield.iac.iac_scan_models import IaCDiffScanResult, IaCDiffScanEntities
from pygitguardian.iac_models import IaCFileResult, IaCVulnerability

INCIDENT_SCHEMA = validators.Schema(
    {
        "policy": str,
        "policy_id": validators.Match(r"^GG_IAC_\d{4}$"),
        "line_end": int,
        "line_start": int,
        "description": str,
        "documentation_url": validators.All(str, validators.Match(r"^https://")),
        "component": str,
        "severity": validators.Any("LOW", "MEDIUM", "HIGH", "CRITICAL"),
    }
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
            "all",
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
            "all",
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
            "all",
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
            "all",
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
    assert re.match(r"\d\.\d{1,3}\.\d", json_result["iac_engine_version"])
    assert json_result["type"] == "path_scan"
    assert json_result["total_incidents"] == total_incidents


def assert_file_single_vulnerability_displayed(json_result: Dict[str, Any]):
    file_result = [
        file_result
        for file_result in json_result["entities_with_incidents"]
        if file_result["filename"] == "iac_file_single_vulnerability.tf"
    ]
    assert len(file_result) == 1
    assert (
        S(
            {
                "filename": str,
                "incidents": validators.All(
                    [INCIDENT_SCHEMA], validators.Length(min=1, max=1)
                ),
                "total_incidents": 1,
            }
        )
        == file_result[0]
    )
    assert file_result[0]["incidents"][0]["policy_id"] == "GG_IAC_0001"


def assert_file_multiple_vulnerabilities_displayed(json_result: Dict[str, Any]):
    file_result = [
        file_result
        for file_result in json_result["entities_with_incidents"]
        if file_result["filename"] == "iac_file_multiple_vulnerabilities.tf"
    ]
    assert len(file_result) == 1
    assert (
        S(
            {
                "filename": str,
                "incidents": validators.All(
                    [INCIDENT_SCHEMA], validators.Length(min=2, max=2)
                ),
                "total_incidents": 2,
            }
        )
        == file_result[0]
    )
    assert {incident["policy_id"] for incident in file_result[0]["incidents"]} == {
        "GG_IAC_0002",
        "GG_IAC_0003",
    }

def test_iac_scan_diff():
    # run
    output_handler = IaCJSONOutputHandler(True)
    raw_json = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="id",
            result=IaCDiffScanResult(
                id="id",
                type="type",
                iac_engine_version="",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[
                        IaCFileResult(
                            filename="/path/to/file.tf",
                            incidents=[
                                IaCVulnerability(
                                    component="COMPONENT",
                                    description="DESCRIPTION",
                                    documentation_url="DOCUMENTATION_URL",
                                    line_start=0,
                                    line_end=0,
                                    policy="POLICY",
                                    policy_id="POLICY_ID",
                                    severity="SEVERITY"
                                )
                            ]
                        )
                    ], unchanged=[], deleted=[]
                )
            ),
        )
    )
    parsed_json = json.loads(raw_json)
    
    assert parsed_json == {
        'added_vulns': [
            {
                'filename': '/path/to/file.tf',
                'incidents': [
                    {
                        'policy': 'POLICY',
                        'policy_id': 'POLICY_ID',
                        'line_end': 0,
                        'line_start': 0,
                        'description': 'DESCRIPTION',
                        'documentation_url': 'DOCUMENTATION_URL',
                        'component': 'COMPONENT',
                        'severity': 'SEVERITY'
                    }
                ],
                'total_incidents': 0
            }
        ],
        'persisting_vulns': [],
        'removed_vulns': []
    }

if __name__ == "__init__":
    test_iac_scan_diff()