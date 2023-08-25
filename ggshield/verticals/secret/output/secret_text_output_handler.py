import shutil
from copy import deepcopy
from io import StringIO
from typing import ClassVar, Dict, List, Optional, Set, Tuple

from pygitguardian.client import VERSIONS
from pygitguardian.models import Match, PolicyBreak

from ggshield.core.errors import UnexpectedError
from ggshield.core.filter import censor_content, leak_dictionary_by_ignore_sha
from ggshield.core.lines import Line, get_lines_from_content, get_offset, get_padding
from ggshield.core.match_indices import find_match_indices
from ggshield.core.text_utils import (
    STYLE,
    clip_long_line,
    file_info,
    format_text,
    pluralize,
    translate_validity,
)
from ggshield.utils.git_shell import Filemode

from ..secret_scan_collection import Result, SecretScanCollection
from .secret_output_handler import SecretOutputHandler


# MAX_SECRET_SIZE controls the max length of |-----| under a secret
# avoids occupying a lot of space in a CI terminal.
MAX_SECRET_SIZE = 80


class SecretTextOutputHandler(SecretOutputHandler):
    nb_lines: ClassVar[int] = 3

    def _process_scan_impl(self, scan: SecretScanCollection, top: bool = True) -> str:
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
            if (
                (not known_secret and not show_only_known_secrets)
                or (known_secret and show_only_known_secrets)
                or not self.ignore_known_secrets
            ):
                number_of_displayed_secrets += 1

                result_buf.write(
                    policy_break_header(policy_breaks, ignore_sha, known_secret)
                )

                for policy_break in policy_breaks:
                    policy_break.matches = SecretTextOutputHandler.make_matches(
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


def leak_message_located(
    flat_matches_dict: Dict[int, List[Match]],
    lines: List[Line],
    padding: int,
    offset: int,
    nb_lines: int,
    clip_long_lines: bool = False,
) -> str:
    """
    Display leak message of an incident with location in content.

    :param lines: The lines list
    :param line_index: The last index in the line
    :param detector_line: The list of detectors object in the line
    :param padding: The line padding
    :param offset: The offset due to the line display
    """
    leak_msg = StringIO()
    max_width = shutil.get_terminal_size()[0] - offset if clip_long_lines else 0

    lines_to_display = get_lines_to_display(flat_matches_dict, lines, nb_lines)

    old_line_number: Optional[int] = None
    for line_number in sorted(lines_to_display):
        multiline_end = None
        line = lines[line_number]
        line_content = line.content

        if old_line_number is not None and line_number - old_line_number != 1:
            leak_msg.write(format_line_count_break(padding))

        # The current line number matches a found secret
        if line_number in flat_matches_dict:
            for flat_match in sorted(
                flat_matches_dict[line_number],
                key=lambda x: x.index_start,  # type: ignore
            ):
                is_multiline = flat_match.line_start != flat_match.line_end

                if is_multiline:
                    detector_position = float("inf"), float("-inf")

                    # Iterate on the different (and consecutive) lines of the secret
                    for match_line_index, match_line in enumerate(
                        flat_match.match.splitlines(False)
                    ):
                        multiline_line_number = line_number + match_line_index
                        leak_msg.write(
                            lines[multiline_line_number].build_line_count(
                                padding, is_secret=True
                            )
                        )

                        if match_line_index == 0:
                            # The first line of the secret may contain something else
                            # before
                            formatted_line, secret_position = format_line_with_secret(
                                line_content,
                                flat_match.index_start,
                                len(line_content),
                                max_width,
                            )
                        elif multiline_line_number == flat_match.line_end:
                            # The last line of the secret may contain something else
                            # after
                            last_line_content = lines[flat_match.line_end].content
                            formatted_line, secret_position = format_line_with_secret(
                                last_line_content, 0, len(match_line), max_width
                            )
                            multiline_end = multiline_line_number
                        else:
                            # All the other lines have nothing else but a part of the
                            # secret in them
                            formatted_line, secret_position = format_line_with_secret(
                                match_line, 0, len(match_line), max_width
                            )
                        leak_msg.write(formatted_line)

                        detector_position = (
                            min(detector_position[0], secret_position[0]),
                            max(detector_position[1], secret_position[1]),
                        )

                else:
                    leak_msg.write(line.build_line_count(padding, is_secret=True))
                    formatted_line, detector_position = format_line_with_secret(
                        line_content,
                        flat_match.index_start,
                        flat_match.index_end,
                        max_width,
                    )
                    leak_msg.write(formatted_line)

                detector_position = int(detector_position[0]), int(detector_position[1])
                detector = format_detector(flat_match.match_type, *detector_position)
                leak_msg.write(display_detector(detector, offset))

        # The current line is just here for context
        else:
            leak_msg.write(line.build_line_count(padding, is_secret=False))
            if clip_long_lines:
                line_content = clip_long_line(line_content, max_width, after=True)
            leak_msg.write(f"{display_patch(line_content)}\n")

        old_line_number = multiline_end if multiline_end else line_number

    return leak_msg.getvalue()


def flatten_policy_breaks_by_line(
    policy_breaks: List[PolicyBreak],
) -> Dict[int, List[Match]]:
    """
    flatten_policy_breaks_by_line flatens a list of occurrences with the
    same ignore SHA into a dict of incidents.
    """
    flat_match_dict: Dict[int, List[Match]] = dict()
    for policy_break in policy_breaks:
        for match in policy_break.matches:
            assert match.line_start is not None
            assert match.line_end is not None
            flat_match_list = flat_match_dict.get(match.line_start)
            if flat_match_list and not any(
                match.index_start == flat_match.index_start
                for flat_match in flat_match_list
            ):
                flat_match_list.append(match)
            else:
                flat_match_dict[match.line_start] = [match]

    return flat_match_dict


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
                    context_before, context_max_length // 2, before=True
                )
                context_after = clip_long_line(
                    context_after, context_max_length // 2, after=True
                )
            # Only the before context is too long, clip it but use the maximum space
            # available
            elif len(context_before) > context_max_length // 2:
                context_before = clip_long_line(
                    context_before, context_max_length - len(context_after), before=True
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


def get_lines_to_display(
    flat_matches_dict: Dict[int, List[Match]], lines: List, nb_lines: int
) -> Set[int]:
    """Retrieve the line indexes to display in the content with no secrets."""
    lines_to_display: Set[int] = set()

    for line in sorted(flat_matches_dict):
        for match in flat_matches_dict[line]:
            assert match.line_start is not None
            assert match.line_end is not None
            lines_to_display.update(
                range(max(match.line_start - nb_lines + 1, 0), match.line_start + 1)
            )
            if match.line_end + 1 <= len(lines):
                lines_to_display.update(
                    range(
                        match.line_end + 1, min(match.line_end + nb_lines, len(lines))
                    )
                )

    return lines_to_display


def format_line_count_break(padding: int) -> str:
    """Return the line count break."""
    return format_text(
        " " * max(0, padding - len("...")) + "...\n", STYLE["detector_line_start"]
    )
