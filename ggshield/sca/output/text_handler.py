from io import StringIO
from typing import ClassVar, Optional

from ggshield.core.constants import IncidentStatus
from ggshield.core.text_utils import STYLE, file_info, format_text
from ggshield.sca.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)
from ggshield.sca.output.handler import SCAOutputHandler
from ggshield.sca.sca_scan_models import (
    SCALocationVulnerability,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)


class SCATextOutputHandler(SCAOutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_all_impl(self, scan: SCAScanAllVulnerabilityCollection) -> str:
        scan_buf = StringIO()

        # We precise is not None as __bool__ have been overriden for pygitguardian
        # Base class
        if scan.result is not None:
            # List incidents if any
            for file_result in scan.result.found_package_vulns:
                scan_buf.write(
                    self.process_sca_file_result(
                        file_result, incident_status=IncidentStatus.DETECTED
                    )
                )

            # Show no incidents if none
            if len(scan.result.found_package_vulns) == 0:
                scan_buf.write(no_sca_vulnerabilities())
        return scan_buf.getvalue()

    def _process_scan_diff_impl(self, scan: SCAScanDiffVulnerabilityCollection) -> str:
        scan_buf = StringIO()

        # We precise is not None as __bool__ have been overriden for pygitguardian
        # Base class
        if scan.result is not None:
            # Added vulnerabilities
            # List added incidents if any
            for file_result in scan.result.added_vulns:
                scan_buf.write(
                    self.process_sca_file_result(
                        file_result, incident_status=IncidentStatus.DETECTED
                    )
                )

            # Show no incidents if none
            if len(scan.result.added_vulns) == 0:
                scan_buf.write(no_sca_vulnerability_added())

            # Removed vulnerabilites
            # List removed incidents if any
            for file_result in scan.result.removed_vulns:
                scan_buf.write(
                    self.process_sca_file_result(
                        file_result, incident_status=IncidentStatus.REMOVED
                    )
                )

        return scan_buf.getvalue()

    def process_sca_file_result(
        self,
        file_result: SCALocationVulnerability,
        incident_status: IncidentStatus,
        prefix: Optional[str] = None,
    ) -> str:
        """
        Build readable message on the found incidents for a specific file

        :param file_result: The file results from the IaC scanning API
        :param prefix: (Optional, default = None) Adds a prefix at the
            beginning of a line
        :return: The formatted message to display
        """
        result_buf = StringIO()

        result_buf.write(
            file_info(
                file_result.location,
                # Compute number of incidents in the file
                sum(
                    len(pkg_version.vulns) for pkg_version in file_result.package_vulns
                ),
                incident_status=incident_status,
            )
        )

        incident_n = 1
        for package_version in file_result.package_vulns:
            for vulnerability in package_version.vulns:
                result_buf.write(
                    sca_incident_header(incident_n, package_version, prefix=prefix)
                )

                result_buf.write(sca_incident_severity_line(vulnerability))
                result_buf.write(sca_incident_summary_line(vulnerability))
                result_buf.write(sca_incident_fix_version_line(vulnerability))
                result_buf.write(sca_incident_identifier(vulnerability))
                result_buf.write(sca_incident_cve_ids(vulnerability))

                incident_n += 1

        return result_buf.getvalue()


def no_sca_vulnerabilities() -> str:
    """
    Build a message if no SCA vulnerabilities were found.
    """
    return format_text("\nNo SCA vulnerability has been found.\n", STYLE["no_secret"])


def no_sca_vulnerability_added() -> str:
    """
    Build a message if no SCA vulnerabilities were added.
    """
    return format_text("\nNo SCA vulnerability has been added.\n", STYLE["no_secret"])


def sca_incident_header(
    incident_n: int,
    package_version: SCAVulnerablePackageVersion,
    prefix: Optional[str] = None,
) -> str:
    return "\n{}{} Incident {} ({}): {}@{}\n".format(
        format_text(">>>", STYLE["detector_line_start"]),
        "" if prefix is None else f" {prefix}:",
        incident_n,
        format_text("SCA", STYLE["detector"]),
        format_text(package_version.package_full_name, STYLE["detector"]),
        format_text(package_version.version, STYLE["detector"]),
    )


def sca_incident_severity_line(vulnerability: SCAVulnerability) -> str:
    """
    Returns the severity line, with associated style
    """
    if vulnerability.severity.lower() == "critical":
        severity_string = "Critical"
        style = STYLE["sca_vulnerability_critical"]
    elif vulnerability.severity.lower() == "high":
        severity_string = "High"
        style = STYLE["sca_vulnerability_high"]
    elif vulnerability.severity.lower() == "medium":
        severity_string = "Medium"
        style = STYLE["sca_vulnerability_medium"]
    elif vulnerability.severity.lower() == "low":
        severity_string = "Low"
        style = STYLE["sca_vulnerability_low"]
    else:  # In the other case, print `severity`
        severity_string = vulnerability.severity
        style = STYLE["sca_vulnerability_unknown"]

    return "Severity: {}\n".format(
        format_text(severity_string, style),
    )


def sca_incident_summary_line(vulnerability: SCAVulnerability) -> str:
    return f"Summary: {vulnerability.summary}\n"


def sca_incident_fix_version_line(vulnerability: SCAVulnerability) -> str:
    """
    Return the fixed version information if exists.
    """
    if vulnerability.fixed_version is not None:
        return f"A fix is available at version {vulnerability.fixed_version}\n"

    return "No fix is currently available.\n"


def sca_incident_cve_ids(vulnerability: SCAVulnerability) -> str:
    if not vulnerability.cve_ids:
        cve_str = "-"
    else:
        cve_str = ", ".join(vulnerability.cve_ids)
    return f"CVE IDs: {cve_str}\n"


def sca_incident_identifier(vulnerability: SCAVulnerability) -> str:
    identifier = vulnerability.identifier
    # TODO Remove clause when identifier field is in production on backend side (v2.36)
    if identifier is None:
        return ""
    return f"Identifier: {identifier}\n"
