from typing import List

from pygitguardian.sca_models import (
    SCALocationVulnerability,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)


def filter_unignored_vulnerabilities(
    vulnerabilities: List[SCAVulnerability],
) -> List[SCAVulnerability]:
    """Removes ignored vulnerabilities from the given list"""
    return [vuln for vuln in vulnerabilities if vuln.status != "IGNORED"]


def filter_unignored_location_vulnerabilities(
    locations: List[SCALocationVulnerability],
) -> List[SCALocationVulnerability]:
    """
    Removes all ignored vulnerabilities from all locations.
    Removes locations and nested objects if they are empty.
    """
    unignored_locations: List[SCALocationVulnerability] = []
    for location in locations:
        unignored_package_vulns: List[SCAVulnerablePackageVersion] = []
        for package_vuln in location.package_vulns:
            unignored_vulns = filter_unignored_vulnerabilities(package_vuln.vulns)
            if len(unignored_vulns) > 0:
                unignored_package_vulns.append(
                    SCAVulnerablePackageVersion(
                        package_full_name=package_vuln.package_full_name,
                        version=package_vuln.version,
                        ecosystem=package_vuln.ecosystem,
                        dependency_type=package_vuln.dependency_type,
                        vulns=unignored_vulns,
                    )
                )
        if len(unignored_package_vulns) > 0:
            unignored_locations.append(
                SCALocationVulnerability(
                    location=location.location,
                    package_vulns=unignored_package_vulns,
                )
            )
    return unignored_locations
