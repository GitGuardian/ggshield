import json
import re
from pathlib import Path
from typing import Any, Dict

import pytest
import voluptuous.validators as validators
from click.testing import CliRunner, Result
from pygitguardian.iac_models import IaCFileResult
from pytest_voluptuous import S

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.verticals.iac.output.iac_json_output_handler import IaCJSONOutputHandler
from tests.conftest import (
    IAC_MULTIPLE_VULNERABILITIES,
    IAC_NO_VULNERABILITIES,
    IAC_SINGLE_VULNERABILITY,
)
from tests.unit.conftest import my_vcr
from tests.unit.verticals.iac.utils import (
    generate_diff_scan_collection,
    generate_path_scan_collection,
    generate_vulnerability,
)


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
def test_display_single_vulnerabilities(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_single_vulnerability.tf").write_text(IAC_SINGLE_VULNERABILITY)

    cli_fs_runner.mix_stderr = False
    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            "--json",
            str(tmp_path),
        ],
    )

    json_result = assert_has_beta_warning_and_load_json(result)
    assert_iac_version_displayed(json_result, 1)
    assert_file_single_vulnerability_displayed(json_result)


@my_vcr.use_cassette("test_iac_scan_multiple_vulnerabilities")
def test_display_multiple_vulnerabilities(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_multiple_vulnerabilities.tf").write_text(
        IAC_MULTIPLE_VULNERABILITIES
    )

    cli_fs_runner.mix_stderr = False
    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            "--json",
            str(tmp_path),
        ],
    )

    json_result = assert_has_beta_warning_and_load_json(result)
    assert_iac_version_displayed(json_result, 2)
    assert_file_multiple_vulnerabilities_displayed(json_result)


@my_vcr.use_cassette("test_iac_scan_no_vulnerabilities")
def test_display_no_vulnerability(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_no_vulnerabilities.tf").write_text(IAC_NO_VULNERABILITIES)

    cli_fs_runner.mix_stderr = False
    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            "--json",
            str(tmp_path),
        ],
    )

    json_result = assert_has_beta_warning_and_load_json(result)
    assert_iac_version_displayed(json_result, 0)
    assert len(json_result["entities_with_incidents"]) == 0


@my_vcr.use_cassette("test_iac_scan_multiple_files")
def test_display_multiple_files(tmp_path: Path, cli_fs_runner: CliRunner):
    (tmp_path / "iac_file_single_vulnerability.tf").write_text(IAC_SINGLE_VULNERABILITY)
    (tmp_path / "iac_file_multiple_vulnerabilities.tf").write_text(
        IAC_MULTIPLE_VULNERABILITIES
    )
    (tmp_path / "iac_file_no_vulnerabilities.tf").write_text(IAC_NO_VULNERABILITIES)

    cli_fs_runner.mix_stderr = False
    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            "--json",
            str(tmp_path),
        ],
    )

    json_result = assert_has_beta_warning_and_load_json(result)
    assert_iac_version_displayed(json_result, 3)
    assert_file_single_vulnerability_displayed(json_result)
    assert_file_multiple_vulnerabilities_displayed(json_result)


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("scan_type", [ScanMode.DIRECTORY_ALL, ScanMode.DIRECTORY_DIFF])
def test_json_all_output_no_ignored(verbose: bool, scan_type: ScanMode, tmp_path: Path):
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

    output_handler = IaCJSONOutputHandler(verbose=verbose, output=str(output_path))
    process_fn = (
        output_handler.process_scan
        if scan_type == ScanMode.DIRECTORY_ALL
        else output_handler.process_diff_scan
    )
    exit_code = process_fn(collection)

    assert exit_code == ExitCode.SCAN_FOUND_PROBLEMS

    output = json.loads(output_path.read_text())
    assert not hasattr(output, "scan_found")
    entities = (
        output["entities_with_incidents"]
        if scan_type == ScanMode.DIRECTORY_ALL
        else output["entities_with_incidents"]["new"]
    )
    assert len(entities) == 2
    summary = [
        {
            "filename": entity["filename"],
            "policy_ids": [incident["policy_id"] for incident in entity["incidents"]],
        }
        for entity in entities
    ]
    assert str(summary) == str(
        [
            {
                "filename": "iac_file_single_vulnerability.tf",
                "policy_ids": ["GG_IAC_0001"],
            },
            {
                "filename": "iac_file_multiple_vulnerabilities.tf",
                "policy_ids": ["GG_IAC_0003", "GG_IAC_0004"],
            },
        ]
    )


def assert_has_beta_warning_and_load_json(result: Result) -> Dict[str, Any]:
    assert re.search(
        r"This feature is still in beta, its behavior may change in future versions.\n",
        result.stderr,
    )
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
