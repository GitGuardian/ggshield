from copy import deepcopy
from io import StringIO
from typing import ClassVar, List

from pygitguardian.models import Match

from ggshield.core.errors import UnexpectedError
from ggshield.core.filter import censor_content, leak_dictionary_by_ignore_sha
from ggshield.core.text_utils import Line, pluralize
from ggshield.core.utils import Filemode, find_match_indices, get_lines_from_content
from ggshield.output.output_handler import OutputHandler
from ggshield.scan import Result, ScanCollection

from .message import (
    file_info,
    flatten_policy_breaks_by_line,
    leak_message_located,
    no_leak_message,
    no_new_leak_message,
    policy_break_header,
    secrets_engine_version,
)
from .utils import get_offset, get_padding


class TextOutputHandler(OutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_impl(self, scan: ScanCollection, top: bool = True) -> str:
        processed_scan_results = self.process_scan_results(scan)

        scan_buf = StringIO()
        if self.verbose:
            scan_buf.write(secrets_engine_version())
        scan_buf.write(processed_scan_results)
        if not processed_scan_results:
            scan_buf.write(
                no_new_leak_message() if scan.known_secrets_count else no_leak_message()
            )

        if scan.known_secrets_count > 0:
            scan_buf.write(
                f"\nWarning: {scan.known_secrets_count} {pluralize('secret', scan.known_secrets_count)} ignored "
                f"because {pluralize('it is', scan.known_secrets_count, 'they are')} already known by your "
                f"GitGuardian dashboard and you used the `--ignore-known-secrets` option.\n"
            )

            if self.verbose:
                scan_buf.write(self.process_scan_results(scan, True))
            else:
                scan_buf.write("Use `--verbose` for more details.\n")

        return scan_buf.getvalue()

    def process_scan_results(
        self, scan: ScanCollection, show_only_known_secrets: bool = False
    ) -> str:
        results_buf = StringIO()
        if scan.results:
            current_result_buf = StringIO()
            for result in scan.results.results:
                current_result_buf.write(
                    self.process_result(result, show_only_known_secrets)
                )
            current_result_string = current_result_buf.getvalue()

            # We want to show header when at least one result is not empty
            if scan.optional_header and current_result_string:
                results_buf.write(scan.optional_header)

            results_buf.write(current_result_string)

        if scan.scans:
            for sub_scan in scan.scans:
                inner_scan_str = self.process_scan_results(
                    sub_scan, show_only_known_secrets
                )
                results_buf.write(inner_scan_str)

        return results_buf.getvalue()

    def process_result(
        self, result: Result, show_only_known_secrets: bool = False
    ) -> str:
        """
        Build readable message on the found incidents.

        :param result: The result from scanning API
        :param nb_lines: The number of lines to display before and after a secret in the
        patch
        :param show_secrets: Option to show secrets value
        :param show_only_known_secrets: If True, display only known secrets, and only new secrets otherwise
        :return: The formatted message to display
        """
        result_buf = StringIO()

        # policy breaks and matches are modified in the functions leak_dictionary_by_ignore_sha and censor_content.
        # Previously process_result was executed only once, so it did not create any issue.
        # In the future we could rework those functions such that they do not change what is in the result.
        policy_breaks = deepcopy(result.scan.policy_breaks)
        is_patch = result.filemode != Filemode.FILE
        sha_dict = leak_dictionary_by_ignore_sha(policy_breaks)

        if self.show_secrets:
            content = result.content
        else:
            content = censor_content(result.content, policy_breaks)

        lines = get_lines_from_content(content, result.filemode, is_patch)
        padding = get_padding(lines)
        offset = get_offset(padding, is_patch)

        if len(lines) == 0:
            raise UnexpectedError("Parsing of scan result failed.")

        number_of_displayed_secrets = 0
        for ignore_sha, policy_breaks in sha_dict.items():
            known_secret = policy_breaks[0].known_secret
            if (not known_secret and not show_only_known_secrets) or (
                known_secret and show_only_known_secrets
            ):
                number_of_displayed_secrets += 1

                result_buf.write(
                    policy_break_header(policy_breaks, ignore_sha, known_secret)
                )

                for policy_break in policy_breaks:
                    policy_break.matches = TextOutputHandler.make_matches(
                        policy_break.matches, lines, is_patch
                    )

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

        file_info_line = ""
        if number_of_displayed_secrets > 0:
            file_info_line = file_info(result.filename, number_of_displayed_secrets)

        return file_info_line + result_buf.getvalue()

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
