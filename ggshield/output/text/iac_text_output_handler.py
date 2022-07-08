from io import StringIO
from pathlib import Path
from typing import ClassVar, List

from ggshield.output.output_handler import OutputHandler
from ggshield.scan import File, ScanCollection

from ...core.text_utils import Line
from ...core.utils import Filemode, get_lines_from_content
from ...iac.models import IaCFileResult
from .message import (
    file_info,
    iac_engine_version,
    iac_vulnerability_header,
    iac_vulnerability_location,
    iac_vulnerability_location_failed,
    no_iac_vulnerabilities,
)


class IaCTextOutputHandler(OutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_impl(self, scan: ScanCollection) -> str:
        scan_buf = StringIO()
        if scan.optional_header and (scan.iac_result or self.verbose):
            scan_buf.write(scan.optional_header)

        if scan.iac_result:
            scan_buf.write(iac_engine_version(scan.iac_result.iac_engine_version))
            for file_result in scan.iac_result.entities_with_incidents:
                scan_buf.write(
                    self.process_iac_file_result(
                        Path(scan.id) / file_result.filename, file_result
                    )
                )
            if len(scan.iac_result.entities_with_incidents) == 0:
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
            file = File.from_bytes(file_path.read_bytes(), str(file_path))
            lines: List[Line] = get_lines_from_content(
                file.document, Filemode.FILE, False
            )
        except Exception:
            lines = []

        for issue_n, vulnerability in enumerate(file_result.incidents, 1):
            result_buf.write(iac_vulnerability_header(issue_n, vulnerability))
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
