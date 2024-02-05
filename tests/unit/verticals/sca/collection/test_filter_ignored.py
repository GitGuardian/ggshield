from itertools import chain
from typing import List

import pytest
from pygitguardian.sca_models import (
    SCALocationVulnerability,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)

from ggshield.verticals.sca.collection.filter_ignored import (
    filter_unignored_location_vulnerabilities,
    filter_unignored_vulnerabilities,
)


BASE_VULN_INFO = {
    "severity": "HIGH",
    "summary": "Vulnerability summary",
    "cve_ids": ["CVE-0000-0000"],
    "created_at": None,
}


@pytest.fixture
def ignored_vulns() -> List[SCAVulnerability]:
    return [
        SCAVulnerability.from_dict(
            {
                **BASE_VULN_INFO,
                "status": "IGNORED",
                **additional_info,
            }
        )
        for additional_info in (
            {"identifier": "id_0001"},
            {"identifier": "id_0002", "ignore_reason": "ggshield"},
            {
                "identifier": "id_0003",
                "url": "https://github.com/owner/repo/path",
                "ignored_until": "2020-01-01T00:00:00",
                "ignore_reason": "some reason",
                "ignore_comment": "some comment",
            },
        )
    ]


@pytest.fixture
def non_ignored_vulns() -> List[SCAVulnerability]:
    return [
        SCAVulnerability.from_dict(
            {
                **BASE_VULN_INFO,
                **additional_info,
            }
        )
        for additional_info in (
            {"identifier": "id_1001"},
            {"identifier": "id_1002", "status": "TRIGGERED"},
            {"identifier": "id_1003", "url": "https://github.com/owner/repo/path"},
        )
    ]


def generate_package_vuln(*args: List[SCAVulnerability]) -> SCAVulnerablePackageVersion:
    return SCAVulnerablePackageVersion(
        package_full_name="package_name",
        version="1.2.3",
        ecosystem="ecosystem",
        dependency_type="dependency_type",
        vulns=args,
    )


def test_filter_unignored_vulnerabilities(
    ignored_vulns: List[SCAVulnerability], non_ignored_vulns: List[SCAVulnerability]
):
    """
    GIVEN   a list of vulnerabilities
    WHEN    calling filter_unignored_vulnerabilities
    THEN    only non ignored vulnerabilities are returned
    """
    vulns = list(chain(*zip(ignored_vulns, non_ignored_vulns)))
    expected_vulns = [vuln for vuln in vulns if vuln.status != "IGNORED"]
    found_vulns = filter_unignored_vulnerabilities(vulns)
    assert found_vulns == expected_vulns


def test_filter_unignored_files_no_empty(
    ignored_vulns: List[SCAVulnerability], non_ignored_vulns: List[SCAVulnerability]
):
    """
    GIVEN   - a location with only unignored vulns
            - a location with ignored and unignored
            - a location with only ignored vulns
    WHEN    calling filter_unignored_location_vulnerabilities
    THEN    - all ignored vulns are removed
            - the location with no remaining vulns is removed
    """
    files = [
        SCALocationVulnerability(
            location="location1",
            package_vulns=[
                generate_package_vuln(non_ignored_vulns[0], non_ignored_vulns[1]),
            ],
        ),
        SCALocationVulnerability(
            location="location2",
            package_vulns=[
                generate_package_vuln(non_ignored_vulns[2], ignored_vulns[0])
            ],
        ),
        SCALocationVulnerability(
            location="location3",
            package_vulns=[generate_package_vuln(ignored_vulns[1], ignored_vulns[2])],
        ),
    ]

    found_files = filter_unignored_location_vulnerabilities(files)

    assert len(found_files) == 2
    assert found_files[0].package_vulns
    assert [file.location for file in found_files] == ["location1", "location2"]
    assert found_files[0].package_vulns[0].vulns == [
        non_ignored_vulns[0],
        non_ignored_vulns[1],
    ]
    assert found_files[1].package_vulns[0].vulns == [non_ignored_vulns[2]]
