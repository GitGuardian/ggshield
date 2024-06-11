import shutil
from io import StringIO
from typing import Dict, List, Optional, Tuple

from pygitguardian.client import VERSIONS
from pygitguardian.models import PolicyBreak

from ggshield.core.filter import group_policy_breaks_by_ignore_sha
from ggshield.core.lines import Line, get_offset, get_padding
from ggshield.core.text_utils import (
    STYLE,
    clip_long_line,
    file_info,
    format_text,
    pluralize,
    translate_validity,
)

from ..extended_match import ExtendedMatch
from ..secret_scan_collection import Result, SecretScanCollection
from .secret_output_handler import SecretOutputHandler


# MAX_SECRET_SIZE controls the max length of |-----| under a secret
# avoids occupying a lot of space in a CI terminal.
MAX_SECRET_SIZE = 80
# The number of lines to display before and after a secret in the patch
NB_CONTEXT_LINES = 3


class SecretTextOutputHandler(SecretOutputHandler):
    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        """Output Secret Scan Collection in text format"""
        processed_scan_results = self.process_scan_results(scan)

        scan_buf = StringIO()
        if self.verbose:
            scan_buf.write(secrets_engine_version())
        scan_buf.write(processed_scan_results)
        if not processed_scan_results:
            scan_buf.write(
                no_new_leak_message()
                if (self.ignore_known_secrets and scan.known_secrets_count)
                else no_leak_message()
            )

        if self.ignore_known_secrets and scan.known_secrets_count > 0:
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
        self, scan: SecretScanCollection, show_only_known_secrets: bool = False
    ) -> str:
        """Iterate through the scans and sub-scan results to prepare the display."""
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
        :param show_secrets: Option to show secrets value
        :param show_only_known_secrets: If True, display only known secrets, and only new secrets otherwise
        :return: The formatted message to display
        """
        result_buf = StringIO()

        sha_dict = group_policy_breaks_by_ignore_sha(result.scan.policy_breaks)

        if not self.show_secrets:
            result.censor()

        number_of_displayed_secrets = 0
        for ignore_sha, policy_breaks in sha_dict.items():
            known_secret = policy_breaks[0].known_secret
            if (
                (not known_secret and not show_only_known_secrets)
                or (known_secret and show_only_known_secrets)
                or not self.ignore_known_secrets
            ):
                number_of_displayed_secrets += 1

                result_buf.write(
                    policy_break_header(policy_breaks, ignore_sha, known_secret)
                )

                result_buf.write(
                    leak_message_located(
                        flatten_policy_breaks_by_line(policy_breaks),
                        result.is_on_patch,
                        clip_long_lines=not self.verbose,
                    )
                )

        file_info_line = ""
        if number_of_displayed_secrets > 0:
            file_info_line = file_info(result.filename, number_of_displayed_secrets)

        return file_info_line + result_buf.getvalue()


def leak_message_located(
    flat_matches: List[Tuple[Line, List[ExtendedMatch]]],
    is_patch: bool = False,
    clip_long_lines: bool = False,
) -> str:
    """
    Display leak message of an incident with location in content.

    :param flat_matches:  a list of tuples mapping a line to a list of matches starting at that line.
    :param padding: The line padding
    :param offset: The offset due to the line display
    :param is_patch: Whether the content is a patch
    :param clip_long_lines: Whether to clip long lines
    """
    leak_msg = StringIO()
    all_lines = []
    for line, list_matches in flat_matches:
        if not list_matches:
            all_lines.append(line)
        for match in list_matches:
            all_lines.extend(
                match.lines_with_secret,
            )
    padding = get_padding(all_lines)
    offset = get_offset(padding, is_patch)
    max_width = shutil.get_terminal_size()[0] - offset if clip_long_lines else 0

    old_line_number: Optional[int] = None
    for line, matches in flat_matches:
        line_number = line.pre_index or line.post_index
        line_content = line.content

        if (
            line_number is not None
            and old_line_number is not None
            and line_number - old_line_number != 1
        ):
            leak_msg.write(format_line_count_break(padding))

        if not matches:
            # The current line is just here for context
            leak_msg.write(line.build_line_count(padding, is_secret=False))
            if clip_long_lines:
                line_content = clip_long_line(
                    line_content, max_width - int(is_patch), after=True
                )
            leak_msg.write(f"{display_patch(line_content)}\n")
        else:
            # The current line number matches a found secret
            assert line_number is not None  # we cannot have secret in patch hunks
            for match in matches:
                span = match.span
                if len(match.lines_with_secret) == 1:
                    # The secret is on just one line
                    leak_msg.write(line.build_line_count(padding, is_secret=True))
                    formatted_line, detector_position = format_line_with_secret(
                        line_content,
                        span.column_index_start,
                        span.column_index_end,
                        max_width,
                        is_patch,
                    )
                    leak_msg.write(formatted_line)
                else:
                    # The secret is on multiple lines
                    detector_position = float("inf"), float("-inf")
                    for index, line_of_secret in enumerate(match.lines_with_secret):
                        leak_msg.write(
                            line_of_secret.build_line_count(padding, is_secret=True)
                        )
                        secret_start = span.column_index_start if index == 0 else 0
                        secret_end = (
                            span.column_index_end
                            if index == len(match.lines_with_secret) - 1
                            else len(line_of_secret.content)
                        )
                        formatted_line, secret_position = format_line_with_secret(
                            line_of_secret.content,
                            secret_start,
                            secret_end,
                            max_width,
                            is_patch,
                        )
                        leak_msg.write(formatted_line)

                        detector_position = (
                            min(detector_position[0], secret_position[0]),
                            max(detector_position[1], secret_position[1]),
                        )
                    line_number += len(match.lines_with_secret) - 1
                detector_position = int(detector_position[0]), int(detector_position[1])
                detector = format_detector(match.match_type, *detector_position)
                leak_msg.write(display_detector(detector, offset))

        old_line_number = line_number

    return leak_msg.getvalue()


def flatten_policy_breaks_by_line(
    policy_breaks: List[PolicyBreak],
) -> List[Tuple[Line, List[ExtendedMatch]]]:
    """
    flatten_policy_breaks_by_line turns a list of policy breaks into a list of
    tuples of (line, list of matches) mapping a line to a list of matches starting
    at that line. The list is sorted by line number.
    """
    flat_match_dict: Dict[Line, List[ExtendedMatch]] = dict()
    for policy_break in policy_breaks:
        for match in policy_break.matches:
            assert isinstance(match, ExtendedMatch)
            for line in match.lines_before_secret + match.lines_after_secret:
                if line not in flat_match_dict:
                    flat_match_dict[line] = []
            # Only add match to the first line, we will handle multiline at formating
            line = match.lines_with_secret[0]
            if line not in flat_match_dict:
                flat_match_dict[line] = []
            flat_match_dict[line].append(match)
    # Sort the matches per line number
    ordered_flat_match: List[Tuple[Line, List[ExtendedMatch]]] = sorted(
        flat_match_dict.items(),
        key=lambda item: item[0].pre_index or item[0].post_index or -1,
    )
    return ordered_flat_match


def policy_break_header(
    policy_breaks: List[PolicyBreak],
    ignore_sha: str,
    known_secret: bool = False,
) -> str:
    """
    Build a header for the policy break.
    """
    indent = "   "
    validity_msg = (
        f"\n{indent}Validity: {format_text(translate_validity(policy_breaks[0].validity), STYLE['incident_validity'])}"
        if policy_breaks[0].validity
        else ""
    )

    start_line = format_text(">>", STYLE["detector_line_start"])
    policy_break_type = format_text(
        policy_breaks[0].break_type, STYLE["policy_break_type"]
    )
    number_occurrences = format_text(str(len(policy_breaks)), STYLE["occurrence_count"])
    ignore_sha = format_text(ignore_sha, STYLE["ignore_sha"])

    return f"""
{start_line} Secret detected: {policy_break_type}{validity_msg}
{indent}Occurrences: {number_occurrences}
{indent}Known by GitGuardian dashboard: {"YES" if known_secret else "NO"}
{indent}Incident URL: {policy_breaks[0].incident_url if known_secret and policy_breaks[0].incident_url else "N/A"}
{indent}Secret SHA: {ignore_sha}

"""


def no_leak_message() -> str:
    """
    Build a message if no secret is found.
    """
    return format_text("\nNo secrets have been found\n", STYLE["no_secret"])


def no_new_leak_message() -> str:
    """
    Build a message if no new secret is found.
    """
    return format_text("\nNo new secrets have been found\n", STYLE["no_secret"])


def format_line_with_secret(
    line_content: str,
    secret_index_start: int,
    secret_index_end: int,
    max_width: Optional[int] = None,
    is_patch: bool = False,
) -> Tuple[str, Tuple[int, int]]:
    """
    Format a line containing a secret.
    :param line_content: the whole line, as a string
    :param secret_index_start: the index in the line, as an integer, where the secret
    starts
    :param secret_index_end: the index in the line, as an integer, where the secret
    ends
    :param max_width: if set, context will be clipped if needed
    :return The formatted detector as a string, and the position (start and end index)
    of the secret in it.
    """
    context_before = line_content[:secret_index_start]
    secret = line_content[secret_index_start:secret_index_end]
    context_after = line_content[secret_index_end:]
    secret_length = len(secret)

    # Clip the context if it is too long
    if max_width:
        context_max_length = max_width - secret_length
        if len(context_before) + len(context_after) > context_max_length:
            # Both before and after context are too long, cut them to the same size
            if (
                len(context_before) > context_max_length // 2
                and len(context_after) > context_max_length // 2
            ):
                context_before = clip_long_line(
                    context_before,
                    context_max_length // 2,
                    before=True,
                    is_patch=is_patch,
                )
                context_after = clip_long_line(
                    context_after, context_max_length // 2, after=True
                )
            # Only the before context is too long, clip it but use the maximum space
            # available
            elif len(context_before) > context_max_length // 2:
                context_before = clip_long_line(
                    context_before,
                    context_max_length - len(context_after),
                    before=True,
                    is_patch=is_patch,
                )
            # Only the after context is too long, same idea
            elif len(context_after) > context_max_length // 2:
                context_after = clip_long_line(
                    context_after, context_max_length - len(context_before), after=True
                )

    formatted_line = (
        (display_patch(context_before) if context_before else "")
        + display_match_value(secret)
        + (display_patch(context_after) if context_after else "")
        + "\n"
    )

    secret_display_index_start = len(context_before)
    secret_display_index_end = secret_display_index_start + secret_length
    return formatted_line, (secret_display_index_start, secret_display_index_end)


def display_patch(patch: str) -> str:
    """Return the formatted patch."""
    return format_text(patch, STYLE["patch"])


def display_match_value(match_value: str) -> str:
    """Return the formatted match value."""
    return format_text(match_value, STYLE["secret"])


def display_detector(detector: str, offset: int) -> str:
    """Return the formatted detector line."""
    return " " * offset + format_text(detector, STYLE["detector"])


def format_detector(match_type: str, index_start: int, index_end: int) -> str:
    """Return detector object to add in detector_line."""

    detector_size = len(match_type)
    secret_size = index_end - index_start

    display = ""
    if secret_size < MAX_SECRET_SIZE:
        before = "_" * max(1, int(((secret_size - detector_size) - 1) / 2))
        after = "_" * max(1, (secret_size - len(before) - detector_size) - 2)
        display = f"|{before}{match_type}{after}|"

    return " " * index_start + format_text(display, STYLE["detector"]) + "\n"


def secrets_engine_version() -> str:
    return f"\nsecrets-engine-version: {VERSIONS.secrets_engine_version}\n"


def format_line_count_break(padding: int) -> str:
    """Return the line count break."""
    return format_text(
        " " * max(0, padding - len("...")) + "...\n", STYLE["detector_line_start"]
    )
