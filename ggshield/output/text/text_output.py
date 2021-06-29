from io import StringIO
from typing import ClassVar, List, Tuple

import click

from ggshield.filter import censor_content, leak_dictionary_by_ignore_sha
from ggshield.output.output_handler import OutputHandler
from ggshield.scan import Result, ScanCollection
from ggshield.text_utils import LINE_DISPLAY, Line
from ggshield.utils import Filemode, get_lines_from_content, update_policy_break_matches

from .message import (
    file_info,
    flatten_policy_breaks_by_line,
    leak_message_located,
    no_leak_message,
    policy_break_header,
    secrets_engine_version,
)


def get_padding(lines: List[Line]) -> int:
    """Return the number of digit of the maximum line number."""
    # value can be None
    return max(len(str(lines[-1].pre_index or 0)), len(str(lines[-1].post_index or 0)))


def get_offset(padding: int, is_patch: bool = False) -> int:
    """Return the offset due to the line display."""
    if is_patch:
        return len(LINE_DISPLAY["patch"].format("0" * padding, "0" * padding))

    return len(LINE_DISPLAY["file"].format("0" * padding))


class TextHandler(OutputHandler):
    nb_lines: ClassVar[int] = 3

    def process_scan(self, scan: ScanCollection, top: bool = True) -> Tuple[str, int]:
        return_code = 0
        scan_buf = StringIO()
        if scan.optional_header and (scan.results or self.verbose):
            scan_buf.write(scan.optional_header)

        if top and (scan.results or self.verbose):
            scan_buf.write(secrets_engine_version())

        if scan.results:
            return_code = 1
            for result in scan.results:
                scan_buf.write(self.process_result(result))
        else:
            if self.verbose:
                scan_buf.write(no_leak_message())

        if scan.scans:
            for sub_scan in scan.scans:
                inner_scan_str, inner_return_code = self.process_scan(
                    sub_scan, top=False
                )
                scan_buf.write(inner_scan_str)
                return_code = max(return_code, inner_return_code)

        scan_str = scan_buf.getvalue()
        if top:
            if self.output:
                with open(self.output, "w+") as f:
                    click.echo(scan_str, file=f)
            else:
                click.echo(scan_str)

        return scan_str, return_code

    def process_result(self, result: Result) -> str:
        """
        Build readable message on the found incidents.

        :param result: The result from scanning API
        :param nb_lines: The number of lines to display before and after a secret in the
        patch
        :param show_secrets: Option to show secrets value
        :return: The formatted message to display
        """
        result_buf = StringIO()
        policy_breaks = result.scan.policy_breaks
        is_patch = result.filemode != Filemode.FILE
        sha_dict = leak_dictionary_by_ignore_sha(policy_breaks)

        if self.show_secrets:
            content = result.content
        else:
            content = censor_content(result.content, result.scan.policy_breaks)

        lines = get_lines_from_content(
            content, result.filemode, is_patch, self.show_secrets
        )
        padding = get_padding(lines)
        offset = get_offset(padding, is_patch)

        if len(lines) == 0:
            raise click.ClickException("Parsing of scan result failed.")

        result_buf.write(file_info(result.filename, len(sha_dict)))

        for issue_n, (ignore_sha, policy_breaks) in enumerate(sha_dict.items(), 1):
            result_buf.write(policy_break_header(issue_n, policy_breaks, ignore_sha))
            for policy_break in policy_breaks:
                update_policy_break_matches(policy_break.matches, lines, is_patch)

            if policy_breaks[0].policy == "Secrets detection":
                result_buf.write(
                    leak_message_located(
                        flatten_policy_breaks_by_line(policy_breaks),
                        lines,
                        padding,
                        offset,
                        self.nb_lines,
                        clip_long_lines=not self.verbose,
                    )
                )

        return result_buf.getvalue()
