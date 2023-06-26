import shutil
from collections import namedtuple
from io import StringIO
from pathlib import Path
from typing import ClassVar, Dict, Generator, List, Optional

from pygitguardian.iac_models import IaCFileResult, IaCVulnerability

from ggshield.core.text_utils import (
    STYLE,
    Line,
    clip_long_line,
    file_diff_info,
    file_info,
    format_text,
    get_offset,
    get_padding,
    pluralize,
)
from ggshield.core.utils import Filemode, get_lines_from_content
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.collection.iac_path_scan_collection import IaCPathScanCollection
from ggshield.iac.iac_scan_models import IaCDiffScanEntities
from ggshield.iac.output.iac_output_handler import IaCOutputHandler
from ggshield.scan import File


GroupedIncidents = namedtuple(
    "GroupedIncidents", ["name", "new", "unchanged", "deleted"]
)


def group_incidents_by_filename(
    incidents: IaCDiffScanEntities,
) -> Generator[GroupedIncidents, None, None]:
    keys = []
    attrs = ["new", "unchanged", "deleted"]
    attrs_val: Dict[str, dict] = dict()
    for attr in attrs:
        attrs_val[attr] = dict()
        for entry in getattr(incidents, attr):
            key = entry.filename
            if key not in keys:
                keys.append(key)
            attrs_val[attr].setdefault(key, [])
            attrs_val[attr][key].append(entry)
    for key in keys:
        new = attrs_val.get("new", {}).get(key, [])
        unchanged = attrs_val.get("unchanged", {}).get(key, [])
        deleted = attrs_val.get("deleted", {}).get(key, [])
        yield GroupedIncidents(key, new, unchanged, deleted)


class IaCTextOutputHandler(IaCOutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_impl(self, scan: IaCPathScanCollection) -> str:
        scan_buf = StringIO()

        if scan.result is not None:
            # Add iac version on output
            scan_buf.write(iac_engine_version(scan.result.iac_engine_version))
            # List incidents if any
            for file_result in scan.result.entities_with_incidents:
                scan_buf.write(
                    self.process_iac_file_result(
                        Path(scan.id) / file_result.filename, file_result
                    )
                )
            # Show no incidents if none
            if len(scan.result.entities_with_incidents) == 0:
                scan_buf.write(no_iac_vulnerabilities())
        return scan_buf.getvalue()

    def _process_diff_scan_impl_not_verbose(self, scan: IaCDiffScanCollection) -> str:
        scan_buf = StringIO()

        if scan.result is not None:
            # Add iac version on output
            scan_buf.write(iac_engine_version(scan.result.iac_engine_version))
            # Show no incidents if none
            if len(scan.result.entities_with_incidents.new) == 0:
                scan_buf.write(
                    format_text(
                        "\nNo new incidents have been found\n", STYLE["no_secret"]
                    )
                )
            else:
                for filename, new, _, _ in group_incidents_by_filename(
                    scan.result.entities_with_incidents
                ):
                    if len(new) == 0:
                        continue
                    scan_buf.write(file_diff_info(filename, len(new), None, None))
                    # List new incidents if any
                    for file_result in new:
                        scan_buf.write(
                            self.process_iac_diff_result(
                                Path(scan.id) / file_result.filename, file_result
                            )
                        )
            # Show summary
            scan_buf.write(
                diff_scan_summary(
                    scan.result.entities_with_incidents.new,
                    scan.result.entities_with_incidents.unchanged,
                    scan.result.entities_with_incidents.deleted,
                )
            )
        return scan_buf.getvalue()

    def _process_diff_scan_impl_verbose(self, scan: IaCDiffScanCollection) -> str:
        scan_buf = StringIO()

        if scan.result is not None:
            # Add iac version on output
            scan_buf.write(iac_engine_version(scan.result.iac_engine_version))
            # Show no incidents if none
            total_vulns_count = (
                len(scan.result.entities_with_incidents.new)
                + len(scan.result.entities_with_incidents.unchanged)
                + len(scan.result.entities_with_incidents.deleted)
            )
            if total_vulns_count == 0:
                scan_buf.write(no_iac_vulnerabilities())
            else:
                for filename, new, unchanged, deleted in group_incidents_by_filename(
                    scan.result.entities_with_incidents
                ):
                    scan_buf.write(
                        file_diff_info(filename, len(new), len(unchanged), len(deleted))
                    )

                    # List deleted incidents if any
                    for file_result in deleted:
                        scan_buf.write(
                            self.process_iac_diff_result(
                                Path(scan.id) / file_result.filename,
                                file_result,
                                "REMOVED",
                            )
                        )
                    # List unchagned incidents if any
                    for file_result in unchanged:
                        scan_buf.write(
                            self.process_iac_diff_result(
                                Path(scan.id) / file_result.filename,
                                file_result,
                                "PERSISTING",
                            )
                        )
                    # List new incidents if any
                    for file_result in new:
                        scan_buf.write(
                            self.process_iac_diff_result(
                                Path(scan.id) / file_result.filename, file_result, "NEW"
                            )
                        )
            # Show summary
            scan_buf.write(
                diff_scan_summary(
                    scan.result.entities_with_incidents.new,
                    scan.result.entities_with_incidents.unchanged,
                    scan.result.entities_with_incidents.deleted,
                )
            )
        return scan_buf.getvalue()

    def _process_diff_scan_impl(self, scan: IaCDiffScanCollection) -> str:
        if self.verbose:
            return self._process_diff_scan_impl_verbose(scan)
        return self._process_diff_scan_impl_not_verbose(scan)

    def process_iac_file_result(
        self, file_path: Path, file_result: IaCFileResult, prefix: Optional[str] = None
    ) -> str:
        """
        Build readable message on the found incidents for a specific file

        :param file_path: The full path to the file, used to read the content of the file
        :param file_result: The file results from the IaC scanning API
        :return: The formatted message to display
        """
        result_buf = StringIO()

        result_buf.write(file_info(file_result.filename, len(file_result.incidents)))

        try:
            file = File(str(file_path))
            lines: List[Line] = get_lines_from_content(
                file.content, Filemode.FILE, False
            )
        except Exception:
            lines = []

        for issue_n, vulnerability in enumerate(file_result.incidents, 1):
            result_buf.write(
                iac_vulnerability_header(issue_n, vulnerability, prefix=prefix)
            )
            result_buf.write(iac_vulnerability_severity_line(vulnerability.severity))
            if len(lines) == 0:
                result_buf.write(
                    iac_vulnerability_location_failed(
                        vulnerability.line_start, vulnerability.line_end
                    )
                )
            else:
                result_buf.write(
                    iac_vulnerability_location(
                        lines,
                        vulnerability.line_start,
                        vulnerability.line_end,
                        self.nb_lines,
                        clip_long_lines=not self.verbose,
                    )
                )

        return result_buf.getvalue()

    def process_iac_diff_result(
        self, file_path: Path, file_result: IaCFileResult, prefix: Optional[str] = None
    ) -> str:
        """
        Build readable message on the found incidents for a specific file

        :param file_path: The full path to the file, used to read the content of the file
        :param file_result: The file results from the IaC scanning API
        :return: The formatted message to display
        """
        result_buf = StringIO()

        try:
            file = File(str(file_path))
            lines: List[Line] = get_lines_from_content(
                file.content, Filemode.FILE, False
            )
        except Exception:
            lines = []

        for issue_n, vulnerability in enumerate(file_result.incidents, 1):
            result_buf.write(
                iac_vulnerability_header(issue_n, vulnerability, prefix=prefix)
            )
            result_buf.write(iac_vulnerability_severity_line(vulnerability.severity))
            if len(lines) == 0:
                result_buf.write(
                    iac_vulnerability_location_failed(
                        vulnerability.line_start, vulnerability.line_end
                    )
                )
            else:
                result_buf.write(
                    iac_vulnerability_location(
                        lines,
                        vulnerability.line_start,
                        vulnerability.line_end,
                        self.nb_lines,
                        clip_long_lines=not self.verbose,
                    )
                )

        return result_buf.getvalue()


def iac_vulnerability_header(
    issue_n: int, vulnerability: IaCVulnerability, prefix: Optional[str] = None
) -> str:
    """
    Build a header for the iac policy break.
    """
    return "\n{}{} Incident {} ({}): {}: {} ({})\n".format(
        format_text(">>>", STYLE["detector_line_start"]),
        "" if prefix is None else f" {prefix}:",
        issue_n,
        format_text("IaC", STYLE["detector"]),
        format_text(vulnerability.component, STYLE["detector"]),
        format_text(vulnerability.policy, STYLE["policy"]),
        format_text(vulnerability.policy_id, STYLE["policy"]),
    )


def iac_vulnerability_severity_line(severity: str) -> str:
    """
    Build a line to output the severity of a vulnerability
    """
    if severity == "CRITICAL":
        severity_string = "Critical"
        style = STYLE["iac_vulnerability_critical"]
    elif severity == "HIGH":
        severity_string = "High"
        style = STYLE["iac_vulnerability_high"]
    elif severity == "MEDIUM":
        severity_string = "Medium"
        style = STYLE["iac_vulnerability_medium"]
    elif severity == "LOW":
        severity_string = "Low"
        style = STYLE["iac_vulnerability_low"]
    else:  # In the other case, print `severity``
        severity_string = severity
        style = STYLE["iac_vulnerability_unknown"]

    return f"Severity: {format_text(severity_string, style)}\n"


def iac_vulnerability_location(
    lines: List[Line],
    line_start: int,
    line_end: int,
    nb_lines: int,
    clip_long_lines: bool = False,
) -> str:
    msg = StringIO()
    padding = get_padding(lines)
    offset = get_offset(padding)
    max_width = shutil.get_terminal_size()[0] - offset if clip_long_lines else 0
    for line_nb in range(
        max(0, line_start - nb_lines), min(len(lines) - 1, line_end + nb_lines)
    ):
        msg.write(
            lines[line_nb].build_line_count(
                padding, line_start - 1 <= line_nb <= line_end - 1
            )
        )
        line_content = lines[line_nb].content

        if max_width:
            line_content = clip_long_line(line_content, max_width, after=True)
        msg.write(f"{line_content}\n")
    return msg.getvalue()


def iac_vulnerability_location_failed(
    line_start: int,
    line_end: int,
) -> str:
    return f"\nFailed to read from the original file.\nThe incident was found between lines {line_start} and {line_end}\n"  # noqa: E501


def iac_engine_version(iac_engine_version: str) -> str:
    return f"\niac-engine-version: {iac_engine_version}\n"


def no_iac_vulnerabilities() -> str:
    """
    Build a message if no IaC vulnerabilities were found.
    """
    return format_text("\nNo incidents have been found\n", STYLE["no_secret"])


def diff_scan_summary(
    new: List[IaCFileResult],
    unchanged: List[IaCFileResult],
    deleted: List[IaCFileResult],
) -> str:
    def detail(entries: List[IaCFileResult]) -> str:
        count: Dict[str, int] = dict()
        for entry in entries:
            for incident in entry.incidents:
                count.setdefault(incident.severity, 0)
                count[incident.severity] += 1
        formatted_count = [f"{key}: {val}" for key, val in count.items()]
        if len(formatted_count) == 0:
            return ""
        return f" ({', '.join(formatted_count)})"

    buf = StringIO()
    buf.write("\nSummary of changes:\n")
    buf.write(
        f'[-] {len(deleted)} {pluralize("incident", len(deleted), "incidents")} deleted{detail(deleted)}\n'
    )
    buf.write(
        f'[~] {len(unchanged)} {pluralize("incident", len(unchanged), "incidents")} remaining{detail(unchanged)}\n'
    )
    buf.write(
        f'[+] {len(new)} new {pluralize("incident", len(new), "incidents")} detected{detail(new)}\n'
    )
    return buf.getvalue()
