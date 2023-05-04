import shutil
from io import StringIO
from pathlib import Path
from typing import ClassVar, List

from pygitguardian.iac_models import IaCFileResult, IaCVulnerability

from ggshield.core.text_utils import (
    STYLE,
    Line,
    clip_long_line,
    file_info,
    format_text,
    get_offset,
    get_padding,
)
from ggshield.core.utils import Filemode, get_lines_from_content
from ggshield.scan import File

from ..iac_scan_collection import IaCScanCollection
from .iac_output_handler import IaCOutputHandler


class IaCTextOutputHandler(IaCOutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_impl(self, scan: IaCScanCollection) -> str:
        scan_buf = StringIO()

        if scan.result:
            scan_buf.write(iac_engine_version(scan.result.iac_engine_version))
            for file_result in scan.result.entities_with_incidents:
                scan_buf.write(
                    self.process_iac_file_result(
                        Path(scan.id) / file_result.filename, file_result
                    )
                )
            if len(scan.result.entities_with_incidents) == 0:
                scan_buf.write(no_iac_vulnerabilities())
        return scan_buf.getvalue()

    def process_iac_file_result(
        self, file_path: Path, file_result: IaCFileResult
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
            result_buf.write(iac_vulnerability_header(issue_n, vulnerability))
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


def iac_vulnerability_header(issue_n: int, vulnerability: IaCVulnerability) -> str:
    """
    Build a header for the iac policy break.
    """
    return "\n{} Incident {} ({}): {}: {} ({})\n".format(
        format_text(">>>", STYLE["detector_line_start"]),
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
