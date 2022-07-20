from io import StringIO
from typing import ClassVar, List, cast

import click
from pygitguardian.models import Match

from ggshield.core.filter import censor_content, leak_dictionary_by_ignore_sha
from ggshield.core.text_utils import Line
from ggshield.core.utils import Filemode, find_match_indices, get_lines_from_content
from ggshield.output.output_handler import OutputHandler
from ggshield.scan import Result, Results, ScanCollection

from .message import (
    file_info,
    flatten_policy_breaks_by_line,
    leak_message_located,
    no_leak_message,
    policy_break_header,
    secrets_engine_version,
)
from .utils import get_offset, get_padding


class TextOutputHandler(OutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_impl(self, scan: ScanCollection, top: bool = True) -> str:
        scan_buf = StringIO()
        if scan.optional_header and (scan.has_results or self.verbose):
            scan_buf.write(scan.optional_header)

        if top and (scan.has_results or self.verbose):
            scan_buf.write(secrets_engine_version())

        if scan.has_results:
            for result in cast(Results, scan.results).results:
                scan_buf.write(self.process_result(result))
        else:
            has_results = False
            if scan.scans:
                has_results = any(x.has_results for x in scan.scans)

            if top and not has_results:
                scan_buf.write(no_leak_message())

        if scan.scans:
            for sub_scan in scan.scans:
                inner_scan_str = self._process_scan_impl(sub_scan, top=False)
                scan_buf.write(inner_scan_str)

        return scan_buf.getvalue()

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

        lines = get_lines_from_content(content, result.filemode, is_patch)
        padding = get_padding(lines)
        offset = get_offset(padding, is_patch)

        if len(lines) == 0:
            raise click.ClickException("Parsing of scan result failed.")

        result_buf.write(file_info(result.filename, len(sha_dict)))

        for issue_n, (ignore_sha, policy_breaks) in enumerate(sha_dict.items(), 1):
            result_buf.write(policy_break_header(issue_n, policy_breaks, ignore_sha))
            for policy_break in policy_breaks:
                policy_break.matches = TextOutputHandler.make_matches(
                    policy_break.matches, lines, is_patch
                )

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

    @staticmethod
    def make_matches(
        matches: List[Match], lines: List[Line], is_patch: bool
    ) -> List[Match]:
        res = []
        for match in matches:
            if match.index_start is None or match.index_end is None:
                res.append(match)
                continue
            indices = find_match_indices(match, lines, is_patch)
            res.append(
                Match(
                    match=match.match,
                    match_type=match.match_type,
                    index_start=indices.index_start,
                    index_end=indices.index_end,
                    line_start=indices.line_index_start,
                    line_end=indices.line_index_end,
                )
            )
        return res
