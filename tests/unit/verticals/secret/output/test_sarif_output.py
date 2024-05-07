import json
from typing import Any, Dict, TypedDict
from unittest import mock

import pytest
from pygitguardian.models import PolicyBreak, ScanResult
from pytest_voluptuous import S
from voluptuous import Optional as VOptional
from voluptuous import validators

from ggshield.core.scan import Commit
from ggshield.verticals.secret import Result, Results, SecretScanCollection
from ggshield.verticals.secret.output import SecretSARIFOutputHandler
from ggshield.verticals.secret.output.secret_sarif_output_handler import SCHEMA_URL
from tests.unit.conftest import (
    _MULTI_SECRET_ONE_LINE_FULL_PATCH,
    _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    _MULTIPLE_SECRETS_PATCH,
    _MULTIPLE_SECRETS_SCAN_RESULT,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
)


VERSION_VALIDATOR = validators.Match(r"\d+\.\d+\.\d+")


TOOL_SCHEMA = S(
    {
        "driver": {
            "organization": "GitGuardian",
            "name": "ggshield",
            "informationUri": str,
            "version": VERSION_VALIDATOR,
        },
        "extensions": [
            {
                "name": str,
                "version": VERSION_VALIDATOR,
            }
        ],
    }
)

EMPTY_RESULT_SCHEMA = S(
    {
        "version": "2.1.0",
        "$schema": SCHEMA_URL,
        "runs": [{"tool": TOOL_SCHEMA, "results": []}],
    }
)

MIN_1_INT = validators.Range(min=1)

SARIF_PHYSICAL_LOCATION_DICT_SCHEMA = S(
    {
        "artifactLocation": {
            "uri": str,
        },
        "region": {
            "startLine": MIN_1_INT,
            "startColumn": MIN_1_INT,
            "endLine": MIN_1_INT,
            "endColumn": MIN_1_INT,
        },
    }
)

SARIF_RESULT_DICT_SCHEMA = S(
    {
        "ruleId": str,
        "level": "error",
        "message": {
            "text": str,
            "markdown": str,
        },
        "locations": [
            {
                "physicalLocation": SARIF_PHYSICAL_LOCATION_DICT_SCHEMA,
            }
        ],
        "relatedLocations": [
            {
                "id": int,
                "physicalLocation": SARIF_PHYSICAL_LOCATION_DICT_SCHEMA,
                "message": {"text": str},
            }
        ],
        "partialFingerprints": {"secret/v1": str},
        VOptional("hostedViewerUri"): str,
    }
)

SCHEMA_WITH_INCIDENTS = S(
    {
        "version": "2.1.0",
        "$schema": SCHEMA_URL,
        "runs": [{"tool": TOOL_SCHEMA, "results": [SARIF_RESULT_DICT_SCHEMA]}],
    }
)


@pytest.fixture()
def init_secrets_engine_version():
    # Init secrets engine version: it's not set if we don't make an API call
    with mock.patch(
        "ggshield.verticals.secret.output.secret_sarif_output_handler.VERSIONS"
    ) as versions:
        versions.secrets_engine_version = "3.14.1"
        yield


def test_sarif_output_no_secrets(init_secrets_engine_version):
    """
    GIVEN an empty scan collection
    WHEN SecretSARIFOutputHandler runs on it
    THEN it outputs an empty SARIF document
    """
    scan = SecretScanCollection(id="path", type="test", results=Results())
    handler = SecretSARIFOutputHandler(verbose=True, show_secrets=False)
    output = handler._process_scan_impl(scan)
    dct = json.loads(output)

    assert EMPTY_RESULT_SCHEMA == dct


@pytest.mark.parametrize(
    "patch,scan_result",
    [
        pytest.param(
            _MULTIPLE_SECRETS_PATCH,
            _MULTIPLE_SECRETS_SCAN_RESULT,
            id="_MULTIPLE_SECRETS_PATCH",
        ),
        pytest.param(
            _MULTI_SECRET_ONE_LINE_FULL_PATCH,
            _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
            id="_MULTI_SECRET_ONE_LINE_FULL_PATCH",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH,
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            id="_ONE_LINE_AND_MULTILINE_PATCH",
        ),
    ],
)
def test_sarif_output_for_flat_scan_with_secrets(
    init_secrets_engine_version, patch: str, scan_result: ScanResult
):
    """
    GIVEN a patch containing secrets and a scan result
    WHEN SecretSARIFOutputHandler runs on it
    THEN it outputs a SARIF document pointing to the secrets
    """
    handler = SecretSARIFOutputHandler(verbose=True, show_secrets=False)

    commit = Commit.from_patch(patch)
    scannable = next(commit.get_files())

    result = Result(file=scannable, scan=scan_result)
    results = Results(results=[result])
    scan = SecretScanCollection(id="path", type="test", results=results)

    output = handler._process_scan_impl(scan)
    json_dict = json.loads(output)

    assert SCHEMA_WITH_INCIDENTS == json_dict

    sarif_results = json_dict["runs"][0]["results"]

    # Check each found secret is correctly represented
    for sarif_result, policy_break in zip(sarif_results, scan_result.policy_breaks):
        check_sarif_result(sarif_result, scannable.content, policy_break)

    assert len(sarif_results) == len(scan_result.policy_breaks)


PATCHES_AND_RESULTS = [
    (
        _MULTIPLE_SECRETS_PATCH,
        _MULTIPLE_SECRETS_SCAN_RESULT,
    ),
    (
        _MULTI_SECRET_ONE_LINE_FULL_PATCH,
        _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    ),
    (
        _ONE_LINE_AND_MULTILINE_PATCH,
        _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    ),
]


def test_sarif_output_for_nested_scan(init_secrets_engine_version):
    """
    GIVEN a scan results for 3 patches containing secrets
    WHEN SecretSARIFOutputHandler runs on it
    THEN it outputs a SARIF document pointing to the secrets
    """
    handler = SecretSARIFOutputHandler(verbose=True, show_secrets=False)

    nested_scans = []
    contents = []
    for idx, (patch, scan_result) in enumerate(PATCHES_AND_RESULTS):
        commit = Commit.from_patch(patch, sha=f"abcd{idx}")
        scannable = next(commit.get_files())
        contents.append(scannable.content)

        result = Result(file=scannable, scan=scan_result)
        results = Results(results=[result])
        scan = SecretScanCollection(id=f"nested{idx}", type="test", results=results)
        nested_scans.append(scan)

    scan = SecretScanCollection(id="scan", type="test", scans=nested_scans)

    output = handler._process_scan_impl(scan)
    json_dict = json.loads(output)

    assert SCHEMA_WITH_INCIDENTS == json_dict

    # Create a flat list of policy breaks
    policy_breaks = sum(
        (s.results.results[0].scan.policy_breaks for s in scan.scans), []
    )

    # Check each found secret is correctly represented
    sarif_results = json_dict["runs"][0]["results"]
    for content, sarif_result, policy_break in zip(
        contents, sarif_results, policy_breaks
    ):
        check_sarif_result(sarif_result, content, policy_break)

    assert len(sarif_results) == len(policy_breaks)


def check_sarif_result(
    sarif_result: Dict[str, Any], content: str, policy_break: PolicyBreak
):
    """Check sarif_result contains a representation of policy_break, applied to content"""

    # Check the secret name
    secret_name = sarif_result["ruleId"]
    assert secret_name == policy_break.break_type

    # Check the matches point to the right part of the content. `expected_matches`
    # and `actual matches` are dicts of match_name => matched_text.
    expected_matches = {
        m.match_type: content[m.index_start : m.index_end + 1]
        for m in policy_break.matches
    }

    actual_matches = {}
    for location in sarif_result["relatedLocations"]:
        match_name = location["message"]["text"]
        region = location["physicalLocation"]["region"]
        matched_text = get_content_from_region(content, region)
        actual_matches[match_name] = matched_text

    assert actual_matches == expected_matches


class RegionDict(TypedDict):
    startLine: int
    startColumn: int
    endLine: int
    endColumn: int


def get_content_from_region(content: str, region: RegionDict) -> str:
    # Convert region values into 0-based indices
    # Make end values point *after* the last element
    start_line = region["startLine"] - 1

    # endLine is 1-based but points to the line containing the end, so it does not need
    # to be decreased by 1
    end_line = region["endLine"]

    start_column = region["startColumn"] - 1

    # endColumn is 1-based and points to the character after the match, so it needs to
    # be decreased by 1
    end_column = region["endColumn"] - 1

    lines = content.splitlines()[start_line:end_line]

    # Cut start and end. Do the end first because if we cut the start first then
    # `end_column` will be invalid for 1-line regions
    lines[-1] = lines[-1][:end_column]
    lines[0] = lines[0][start_column:]

    return "\n".join(lines)
