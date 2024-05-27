from collections import Counter
from dataclasses import dataclass, field
from io import StringIO
from typing import ClassVar, Dict, Generator, List, Optional, Union

from pygitguardian.sca_models import (
    SCALocationVulnerability,
    SCAScanAllOutput,
    SCAScanDiffOutput,
)

from ggshield.core.constants import IncidentSeverity, IncidentStatus
from ggshield.core.text_utils import STYLE, file_info, format_text, pluralize
from ggshield.verticals.sca.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)
from ggshield.verticals.sca.output.handler import SCAOutputHandler


@dataclass
class OutputIncidentData:
    package_full_name: str
    version: str
    severity: str
    summary: str
    fixed_version: Optional[str]
    identifier: str
    cve_ids: List[str]

    def sort_key(self) -> IncidentSeverity:
        """IncidentSeverity defines __lt__ to allow sorting"""
        try:
            incident_severity = IncidentSeverity(self.severity)
        except ValueError:
            return IncidentSeverity.UNKNOWN
        return incident_severity


def init_severity_counter() -> Dict[str, int]:
    return {severity.value: 0 for severity in IncidentSeverity}


@dataclass
class OutputLocationData:
    """
    Aggregate SCA incidents data to be printed in one class
    The counters allow to sort according to the number of incidents with each severity
    """

    location: str
    added: List[OutputIncidentData] = field(default_factory=list)
    removed: List[OutputIncidentData] = field(default_factory=list)
    added_counter: Dict[str, int] = field(default_factory=init_severity_counter)
    removed_counter: Dict[str, int] = field(default_factory=init_severity_counter)

    def sort_key(self) -> List[int]:
        return list(self.added_counter.values()) + list(self.removed_counter.values())


def populate_incidents_list(
    result_list: List[SCALocationVulnerability],
    locations_with_incidents: Dict[str, OutputLocationData],
    as_removed_incidents: bool = False,
) -> None:
    """
    Populates dict locations with incidents as OutputLocationData from a list
    of SCALocationVulnerability.
    By default, consider incidents as added incidents.
    If `as_removed_incidents=True`, set them as removed incidents.
    """

    if as_removed_incidents:
        incident_list_key = "removed"
        counter_key = "removed_counter"
    else:
        incident_list_key = "added"
        counter_key = "added_counter"

    for vuln_dep_file in result_list:
        location = vuln_dep_file.location
        if location not in locations_with_incidents:
            locations_with_incidents[location] = OutputLocationData(location=location)

        # Update counter of vulns to sort locations by number of incidents
        for pkg_version_with_vuln in vuln_dep_file.package_vulns:
            for vuln in pkg_version_with_vuln.vulns:
                incidents_list = locations_with_incidents[location].__getattribute__(
                    incident_list_key
                )
                incidents_list.append(
                    OutputIncidentData(
                        package_full_name=pkg_version_with_vuln.package_full_name,
                        version=pkg_version_with_vuln.version,
                        severity=vuln.severity,
                        summary=vuln.summary,
                        fixed_version=vuln.fixed_version,
                        identifier=vuln.identifier,
                        cve_ids=vuln.cve_ids,
                    )
                )

                # Update counter of vulns to sort locations by number of incidents
                locations_with_incidents[location].__getattribute__(counter_key)[
                    vuln.severity.lower()
                ] += 1


def get_sorted_locations(
    result: Union[SCAScanDiffOutput, SCAScanAllOutput], with_removed: bool = False
) -> Generator[OutputLocationData, None, None]:
    """
    Retrieve the locations from a SCAScan output sorted by number of incidents
    for each severity
    Parses removed incidents only if `with_removed` is set to True, in case of a scan diff.
    """

    # Check arguments validity
    if isinstance(result, SCAScanAllOutput) and with_removed:
        raise ValueError(
            "get_sorted_locations cannot be called with with_removed in case of a scan all."
        )

    # First generates a dict of locations with the associated number of incidents
    locations_with_vulns: Dict[str, OutputLocationData] = {}

    # Handle added or existing vulnerabilities
    populate_incidents_list(
        result_list=(
            result.added_vulns
            if isinstance(result, SCAScanDiffOutput)
            else result.found_package_vulns
        ),
        locations_with_incidents=locations_with_vulns,
    )

    # Handle removed ones if required, isinstance check required for pyright
    if isinstance(result, SCAScanDiffOutput) and with_removed:
        populate_incidents_list(
            result_list=result.removed_vulns,
            locations_with_incidents=locations_with_vulns,
            as_removed_incidents=True,
        )

    # Finally yield locations in sorted order
    for vuln_loc in sorted(
        locations_with_vulns.values(), key=lambda elt: elt.sort_key(), reverse=True
    ):
        yield vuln_loc


class SCATextOutputHandler(SCAOutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_all_impl(self, scan: SCAScanAllVulnerabilityCollection) -> str:
        scan_buf = StringIO()

        # We precise is not None as __bool__ have been overriden for pygitguardian
        # Base class
        result_without_ignored = scan.get_result_without_ignored()
        if result_without_ignored is not None:
            # List incidents if any
            for file_result in get_sorted_locations(result_without_ignored):
                scan_buf.write(self.file_header(file_result))
                scan_buf.write(
                    self.process_file_result_incidents(file_result.added, prefix="")
                )

            # Show no incidents if none
            if len(result_without_ignored.found_package_vulns) == 0:
                scan_buf.write(no_sca_vulnerabilities())
        return scan_buf.getvalue()

    def _process_scan_diff_impl(self, scan: SCAScanDiffVulnerabilityCollection) -> str:
        """
        In the non verbose case, only new vulnerabilities are shown in
        text output.
        """
        scan_buf = StringIO()

        # We precise is not None as __bool__ have been overriden for pygitguardian
        # Base class
        result_without_ignored = scan.get_result_without_ignored()
        if result_without_ignored is not None:
            # List added incidents if any
            for file_result in get_sorted_locations(
                result_without_ignored, with_removed=self.verbose
            ):
                scan_buf.write(self.file_header(file_result))
                # Show added vulnerabilities
                scan_buf.write(
                    self.process_file_result_incidents(file_result.added, prefix="NEW")
                )

                # Skip the removed vulns if not verbose
                if not self.verbose:
                    continue

                scan_buf.write(
                    self.process_file_result_incidents(
                        file_result.removed,
                        counter_init=len(file_result.added) + 1,
                        prefix="REMOVED",
                        detailed=False,
                    )
                )

            # Show no incidents if none
            if len(result_without_ignored.added_vulns) == 0:
                scan_buf.write(no_sca_vulnerability_added())

            scan_buf.write(diff_scan_summary(result_without_ignored))

        return scan_buf.getvalue()

    def file_header(self, file_result: OutputLocationData) -> str:
        result_buf = StringIO()
        result_buf.write(
            file_info(
                file_result.location,
                # Compute number of added incidents in the file
                sum(nbr for nbr in file_result.added_counter.values()),
                incident_status=IncidentStatus.DETECTED,
            )
        )
        return result_buf.getvalue()

    def process_file_result_incidents(
        self,
        incident_list: List[OutputIncidentData],
        counter_init: int = 1,
        prefix: str = "",
        detailed: bool = True,
    ) -> str:
        result_buf = StringIO()

        incident_n = counter_init
        for incident in sorted(incident_list, key=lambda x: x.sort_key()):
            result_buf.write(sca_incident_header(incident_n, incident, prefix=prefix))

            result_buf.write(sca_incident_severity_line(incident))
            if detailed:
                result_buf.write(sca_incident_summary_line(incident))
                result_buf.write(sca_incident_fix_version_line(incident))
            result_buf.write(sca_incident_identifier(incident))
            result_buf.write(sca_incident_cve_ids(incident))

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
    package_version: OutputIncidentData,
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


def sca_incident_severity_line(vulnerability: OutputIncidentData) -> str:
    """
    Returns the severity line, with associated style
    """
    if vulnerability.severity.lower() == IncidentSeverity.MALICIOUS:
        severity_string = IncidentSeverity.MALICIOUS.value.capitalize()
        style = STYLE["sca_vulnerability_critical"]
    elif vulnerability.severity.lower() == IncidentSeverity.CRITICAL:
        severity_string = IncidentSeverity.CRITICAL.value.capitalize()
        style = STYLE["sca_vulnerability_critical"]
    elif vulnerability.severity.lower() == IncidentSeverity.HIGH:
        severity_string = IncidentSeverity.HIGH.value.capitalize()
        style = STYLE["sca_vulnerability_high"]
    elif vulnerability.severity.lower() == IncidentSeverity.MEDIUM:
        severity_string = IncidentSeverity.MEDIUM.value.capitalize()
        style = STYLE["sca_vulnerability_medium"]
    elif vulnerability.severity.lower() == IncidentSeverity.LOW:
        severity_string = IncidentSeverity.LOW.value.capitalize()
        style = STYLE["sca_vulnerability_low"]

    else:  # In the other case, print `severity` directly
        severity_string = vulnerability.severity
        style = STYLE["sca_vulnerability_unknown"]

    return "Severity: {}\n".format(
        format_text(severity_string, style),
    )


def sca_incident_summary_line(vulnerability: OutputIncidentData) -> str:
    return f"Summary: {vulnerability.summary}\n"


def sca_incident_fix_version_line(vulnerability: OutputIncidentData) -> str:
    """
    Return the fixed version information if exists.
    """
    if vulnerability.fixed_version is not None:
        return f"A fix is available at version {vulnerability.fixed_version}\n"

    return "No fix is currently available.\n"


def sca_incident_cve_ids(vulnerability: OutputIncidentData) -> str:
    if not vulnerability.cve_ids:
        cve_str = "-"
    else:
        cve_str = ", ".join(vulnerability.cve_ids)
    return f"CVE IDs: {cve_str}\n"


def sca_incident_identifier(vulnerability: OutputIncidentData) -> str:
    identifier = vulnerability.identifier
    # TODO Remove clause when identifier field is in production on backend side (v2.36)
    if identifier is None:
        return ""
    return f"Identifier: {identifier}\n"


def diff_scan_summary(result: SCAScanDiffOutput) -> str:
    added_counter = Counter(
        vuln.severity
        for location in result.added_vulns
        for pkg in location.package_vulns
        for vuln in pkg.vulns
    )
    num_added = sum(added_counter.values())

    removed_counter = Counter(
        vuln.severity
        for location in result.removed_vulns
        for pkg in location.package_vulns
        for vuln in pkg.vulns
    )
    num_removed = sum(removed_counter.values())

    def label_incident(n: int) -> str:
        return pluralize("incident", n, "incidents")

    result_buf = StringIO()

    result_buf.write("\nSummary of changes:\n")
    # removed vulns
    result_buf.write(f"[-] {num_removed} {label_incident(num_removed)} deleted")
    if num_removed:
        severity_counters = ", ".join(
            f"{severity.value.capitalize()}: {removed_counter[severity.value]}"
            for severity in IncidentSeverity
            if severity.value in removed_counter
        )
        result_buf.write(f" ({severity_counters})")
    result_buf.write("\n")

    # added vulns
    result_buf.write(f"[+] {num_added} {label_incident(num_added)} detected")
    if num_added:
        severity_counters = ", ".join(
            f"{severity.value.capitalize()}: {added_counter[severity.value]}"
            for severity in IncidentSeverity
            if severity.value in added_counter
        )
        result_buf.write(f" ({severity_counters})")
    result_buf.write("\n")

    return result_buf.getvalue()
