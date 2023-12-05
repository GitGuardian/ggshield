from typing import List

import pytest
from pygitguardian.iac_models import IaCFileResult, IaCVulnerability

from ggshield.verticals.iac.collection.filter_ignored import (
    filter_unignored_files,
    filter_unignored_incidents,
)


BASE_VULN_INFO = {
    "policy": "A policy",
    "line_end": 3,
    "line_start": 1,
    "description": "A policy description",
    "documentation_url": "https://docs.gitguardian.com/iac-security/policies/GG_IAC_0001",
    "component": "vuln-component",
    "severity": "HIGH",
}


@pytest.fixture
def ignored_vulns() -> List[IaCVulnerability]:
    return [
        IaCVulnerability.from_dict(
            {
                **BASE_VULN_INFO,
                "status": "IGNORED",
                **additional_info,
            }
        )
        for additional_info in (
            {"policy_id": "GG_IAC_0001"},
            {"policy_id": "GG_IAC_0002", "ignore_reason": "ggshield"},
            {
                "policy_id": "GG_IAC_0003",
                "url": "https://github.com/owner/repo/path",
                "ignored_until": "2020-01-01T00:00:00",
                "ignore_reason": "some reason",
                "ignore_comment": "some comment",
            },
        )
    ]


@pytest.fixture
def non_ignored_vulns() -> List[IaCVulnerability]:
    return [
        IaCVulnerability.from_dict(
            {
                **BASE_VULN_INFO,
                **additional_info,
            }
        )
        for additional_info in (
            {"policy_id": "GG_IAC_1001"},
            {"policy_id": "GG_IAC_1002", "status": "TRIGGERED"},
            {"policy_id": "GG_IAC_1003", "url": "https://github.com/owner/repo/path"},
        )
    ]


def test_filter_unignored_incidents(
    ignored_vulns: List[IaCVulnerability], non_ignored_vulns: List[IaCVulnerability]
):
    """
    GIVEN   a list of incidents
    WHEN    calling filter_unignored_incidents
    THEN    only non ignored incidents are returned
    """
    expected_gg_ids = [vuln.policy_id for vuln in non_ignored_vulns]
    found_gg_ids = [
        vuln.policy_id
        for vuln in filter_unignored_incidents([*ignored_vulns, *non_ignored_vulns])
    ]
    assert expected_gg_ids == found_gg_ids


def test_filter_unignored_files(
    ignored_vulns: List[IaCVulnerability], non_ignored_vulns: List[IaCVulnerability]
):
    """
    GIVEN   a list of file results with one ignored and one unignored vulns
    WHEN    calling filter_unignored_files
    THEN    only non ignored incidents in files are returned
    """
    n_files = min(len(ignored_vulns), len(non_ignored_vulns))
    files = [
        IaCFileResult(
            filename=f"file {i}",
            incidents=[
                ignored_vulns[i],
                non_ignored_vulns[i],
            ],
        )
        for i in range(n_files)
    ]
    expected_gg_ids = [vuln.policy_id for vuln in non_ignored_vulns]

    found_files = filter_unignored_files(files)
    for i in range(n_files):
        assert [incident.policy_id for incident in found_files[i].incidents] == [
            expected_gg_ids[i]
        ]


def test_filter_unignored_files_no_empty(
    ignored_vulns: List[IaCVulnerability], non_ignored_vulns: List[IaCVulnerability]
):
    """
    GIVEN   - a file result with only unignored vulns
            - a file result with ignored and unignored
            - a file result with only ignored vulns
    WHEN    calling filter_unignored_files
    THEN    the file with only ignored issues is removed
    """
    files = [
        IaCFileResult(
            filename="file 0",
            incidents=[
                non_ignored_vulns[0],
                non_ignored_vulns[1],
            ],
        ),
        IaCFileResult(
            filename="file 1",
            incidents=[
                non_ignored_vulns[2],
                ignored_vulns[0],
            ],
        ),
        IaCFileResult(
            filename="file 2",
            incidents=[
                ignored_vulns[1],
                ignored_vulns[2],
            ],
        ),
    ]

    found_files = filter_unignored_files(files)
    assert [file.filename for file in found_files] == ["file 0", "file 1"]
