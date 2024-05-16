import shutil
from collections import Counter, defaultdict
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import (
    Any,
    ClassVar,
    DefaultDict,
    Dict,
    Generator,
    List,
    NamedTuple,
    Optional,
)

from pygitguardian.iac_models import (
    IaCDiffScanEntities,
    IaCFileResult,
    IaCVulnerability,
)

from ggshield.core.dirs import get_project_root_dir
from ggshield.core.lines import Line, get_lines_from_content, get_offset, get_padding
from ggshield.core.scan import File
from ggshield.core.text_utils import (
    STYLE,
    clip_long_line,
    file_diff_info,
    file_info,
    format_text,
    pluralize,
)
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.iac.collection.iac_diff_scan_collection import (
    IaCDiffScanCollection,
)
from ggshield.verticals.iac.collection.iac_path_scan_collection import (
    IaCPathScanCollection,
)
from ggshield.verticals.iac.output.iac_output_handler import IaCOutputHandler


class GroupedIncidents(NamedTuple):
    name: str
    new: List[IaCFileResult]
    unchanged: List[IaCFileResult]
    deleted: List[IaCFileResult]


def group_incidents_by_filename(
    incidents: IaCDiffScanEntities,
) -> Generator[GroupedIncidents, None, None]:
    filenames = []
    statuses: Dict[str, DefaultDict] = {
        "new": defaultdict(list),
        "unchanged": defaultdict(list),
        "deleted": defaultdict(list),
    }
    for status in statuses:
        for entry in getattr(incidents, status):
            filename = entry.filename
            if filename not in filenames:
                filenames.append(filename)
            statuses[status].setdefault(filename, [])
            statuses[status][filename].append(entry)
    for filename in filenames:
        new: List[IaCFileResult] = statuses.get("new", {}).get(filename, [])
        unchanged: List[IaCFileResult] = statuses.get("unchanged", {}).get(filename, [])
        deleted: List[IaCFileResult] = statuses.get("deleted", {}).get(filename, [])
        yield GroupedIncidents(filename, new, unchanged, deleted)


class IaCTextOutputHandler(IaCOutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_impl(self, scan: IaCPathScanCollection) -> str:
        scan_buf = StringIO()

        entities_without_ignored = scan.get_entities_without_ignored()
        if scan.result is not None and isinstance(entities_without_ignored, List):
            scan_buf.write(iac_engine_version(scan.result.iac_engine_version))
            # List incidents if any
            source_basedir = get_project_root_dir(Path(scan.id))
            for file_result in entities_without_ignored:
                scan_buf.write(
                    self.process_iac_file_result(
                        source_basedir / file_result.filename, file_result
                    )
                )
            # Show no incidents if none
            if len(entities_without_ignored) == 0:
                scan_buf.write(no_iac_vulnerabilities())
        return scan_buf.getvalue()

    def _process_diff_scan_impl_not_verbose(self, scan: IaCDiffScanCollection) -> str:
        scan_buf = StringIO()

        entities_without_ignored = scan.get_entities_without_ignored()
        if scan.result is not None and isinstance(
            entities_without_ignored, IaCDiffScanEntities
        ):
            # Add iac version on output
            scan_buf.write(iac_engine_version(scan.result.iac_engine_version))
            # Show no incidents if none
            if len(entities_without_ignored.new) == 0:
                scan_buf.write(
                    format_text(
                        "\nNo new incidents have been found\n", STYLE["no_secret"]
                    )
                )
            else:
                source_basedir = get_project_root_dir(Path(scan.id))
                for filename, new, _, _ in group_incidents_by_filename(
                    entities_without_ignored
                ):
                    if not new:
                        continue
                    num_new = sum(len(e.incidents) for e in new)
                    scan_buf.write(file_diff_info(filename, num_new, None, None))
                    # List new incidents if any
                    for file_result in new:
                        scan_buf.write(
                            self.process_iac_diff_result(
                                source_basedir / file_result.filename, file_result
                            )
                        )
            # Show summary
            scan_buf.write(
                diff_scan_summary(
                    entities_without_ignored.new,
                    entities_without_ignored.unchanged,
                    entities_without_ignored.deleted,
                )
            )
        return scan_buf.getvalue()

    def _process_diff_scan_impl_verbose(self, scan: IaCDiffScanCollection) -> str:
        entities_without_ignored = scan.get_entities_without_ignored()
        if scan.result is None or not isinstance(
            entities_without_ignored, IaCDiffScanEntities
        ):
            return ""

        scan_buf = StringIO()
        # Add iac version on output
        scan_buf.write(iac_engine_version(scan.result.iac_engine_version))
        # Show no incidents if none
        num_new = sum(len(e.incidents) for e in entities_without_ignored.new)
        num_unchanged = sum(
            len(e.incidents) for e in entities_without_ignored.unchanged
        )
        num_deleted = sum(len(e.incidents) for e in entities_without_ignored.deleted)
        total_vulns_count = num_new + num_unchanged + num_deleted
        source_basedir = get_project_root_dir(Path(scan.id))
        if total_vulns_count == 0:
            scan_buf.write(no_iac_vulnerabilities())
        else:
            for filename, new, unchanged, deleted in group_incidents_by_filename(
                entities_without_ignored
            ):
                num_new = sum(len(e.incidents) for e in new)
                num_unchanged = sum(len(e.incidents) for e in unchanged)
                num_deleted = sum(len(e.incidents) for e in deleted)
                scan_buf.write(
                    file_diff_info(filename, num_new, num_unchanged, num_deleted)
                )

                # List deleted incidents if any
                for file_result in deleted:
                    scan_buf.write(
                        self.process_iac_diff_result(
                            source_basedir / file_result.filename,
                            file_result,
                            "REMOVED",
                        )
                    )
                # List unchanged incidents if any
                for file_result in unchanged:
                    scan_buf.write(
                        self.process_iac_diff_result(
                            source_basedir / file_result.filename,
                            file_result,
                            "PERSISTING",
                        )
                    )
                # List new incidents if any
                for file_result in new:
                    scan_buf.write(
                        self.process_iac_diff_result(
                            source_basedir / file_result.filename, file_result, "NEW"
                        )
                    )
        # Show summary
        scan_buf.write(
            diff_scan_summary(
                entities_without_ignored.new,
                entities_without_ignored.unchanged,
                entities_without_ignored.deleted,
            )
        )
        return scan_buf.getvalue()

    def _process_diff_scan_impl(self, scan: IaCDiffScanCollection) -> str:
        if self.verbose:
            return self._process_diff_scan_impl_verbose(scan)
        return self._process_diff_scan_impl_not_verbose(scan)

    def _process_skip_scan_impl(self) -> str:
        return "> No IaC files detected. Skipping."

    def _process_skip_diff_scan_impl(self) -> str:
        return "> No IaC files changed. Skipping."

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
            file = File(file_path)
            lines: List[Line] = get_lines_from_content(file.content, Filemode.FILE)
        except Exception:
            lines = []

        for issue_n, vulnerability in enumerate(file_result.incidents, 1):
            result_buf.write(
                iac_vulnerability_header(issue_n, vulnerability, prefix=prefix)
            )
            result_buf.write(
                iac_vulnerability_documentation(vulnerability.documentation_url)
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
            if vulnerability.ignored_until is not None:
                result_buf.write(
                    iac_vulnerability_end_of_ignored_period(vulnerability.ignored_until)
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
            file = File(file_path)
            lines: List[Line] = get_lines_from_content(file.content, Filemode.FILE)
        except Exception:
            lines = []

        for issue_n, vulnerability in enumerate(file_result.incidents, 1):
            result_buf.write(
                iac_vulnerability_header(issue_n, vulnerability, prefix=prefix)
            )
            result_buf.write(
                iac_vulnerability_documentation(vulnerability.documentation_url)
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
            if vulnerability.ignored_until is not None:
                result_buf.write(
                    iac_vulnerability_end_of_ignored_period(vulnerability.ignored_until)
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


def iac_vulnerability_documentation(doc_url: str) -> str:
    return f"More at {doc_url}\n"


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
    return f"\nThe incident was found between lines {line_start} and {line_end}\n"  # noqa: E501


def iac_vulnerability_end_of_ignored_period(
    ignored_until: datetime,
) -> str:
    return f"\nThe incident is no longer ignored in the scan since {ignored_until.strftime('%Y-%m-%d')}\n"  # noqa: E501


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
        def _get_style(severity: str) -> Dict[str, Dict[str, Any]]:
            return STYLE.get(
                f"iac_vulnerability_{severity.lower()}",
                STYLE["iac_vulnerability_unknown"],
            )

        count = Counter(
            incident.severity for entry in entries for incident in entry.incidents
        )
        severity_order = {
            k: i for i, k in enumerate(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        }
        formatted_count = [
            format_text(f"{key}: {val}", _get_style(key))
            for key, val in sorted(
                count.items(), key=lambda x: severity_order.get(x[0], -1)
            )
        ]
        if len(formatted_count) == 0:
            return ""
        return f" ({', '.join(formatted_count)})"

    def label_incident(n: int) -> str:
        return pluralize("incident", n, "incidents")

    num_deleted = sum(len(entry.incidents) for entry in deleted)
    num_unchanged = sum(len(entry.incidents) for entry in unchanged)
    num_new = sum(len(entry.incidents) for entry in new)

    buf = StringIO()
    buf.write("\nSummary of changes:\n")
    buf.write(
        format_text(
            f"[-] {num_deleted} {label_incident(num_deleted)} deleted",
            STYLE[
                "iac_deleted_vulnerability" if num_deleted > 0 else "iac_dim_summary"
            ],
        )
    )
    buf.write(f"{detail(deleted)}\n")
    buf.write(
        format_text(
            f"[~] {num_unchanged} {label_incident(num_unchanged)} remaining",
            STYLE[
                (
                    "iac_remaining_vulnerability"
                    if num_unchanged > 0
                    else "iac_dim_summary"
                )
            ],
        )
    )
    buf.write(f"{detail(unchanged)}\n")
    buf.write(
        format_text(
            f"[+] {num_new} new {label_incident(num_new)} detected",
            STYLE["iac_new_vulnerability" if num_new > 0 else "iac_dim_summary"],
        )
    )
    buf.write(f"{detail(new)}\n")
    return buf.getvalue()
