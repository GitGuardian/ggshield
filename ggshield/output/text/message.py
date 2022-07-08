import os
import shutil
from io import StringIO
from typing import Dict, List, Optional, Set, Tuple

from pygitguardian.client import VERSIONS
from pygitguardian.models import HealthCheckResponse, Match, PolicyBreak

from ggshield.core.text_utils import (
    STYLE,
    Line,
    format_text,
    pluralize,
    translate_validity,
)
from ggshield.iac.models import IaCVulnerability
from ggshield.output.text.utils import get_offset, get_padding


DECORATION_BY_OS = {"posix": "🛡️  ⚔️  🛡️ ", "default": ">>>"}

# MAX_SECRET_SIZE controls the max length of |-----| under a secret
# avoids occupying a lot of space in a CI terminal.
MAX_SECRET_SIZE = 80


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
            flat_match_list = flat_match_dict.get(match.line_start)
            if flat_match_list and not any(
                match.index_start == flat_match.index_start
                for flat_match in flat_match_list
            ):
                flat_match_list.append(match)
            else:
                flat_match_dict[match.line_start] = [match]

    return flat_match_dict


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


def policy_break_header(
    issue_n: int, policy_breaks: List[PolicyBreak], ignore_sha: str
) -> str:
    """
    Build a header for the policy break.
    """
    validity_msg = (
        f" (Validity: {format_text(translate_validity(policy_breaks[0].validity), STYLE['nb_secrets'])}) "
        if policy_breaks[0].validity
        else ""
    )

    return "\n{} Incident {}({}): {}{} (Ignore with SHA: {}) ({} {})\n".format(
        format_text(">>>", STYLE["detector_line_start"]),
        issue_n,
        format_text(policy_breaks[0].policy, STYLE["detector"]),
        format_text(policy_breaks[0].break_type, STYLE["detector"]),
        validity_msg,
        format_text(ignore_sha, STYLE["ignore_sha"]),
        len(policy_breaks),
        pluralize("occurrence", len(policy_breaks), "occurrences"),
    )


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


def clip_long_line(
    content: str,
    max_length: int,
    before: bool = False,
    after: bool = False,
    min_length: int = 10,
) -> str:
    """
    Add a "…" character before and/or after the given string
    if it exceeds a maximum length.
    """
    ellipsis = "…"
    content_length = len(content)
    if content_length > max_length:
        if before and after and content_length > max_length + 1:
            content = (
                ellipsis
                + content[
                    (content_length - max(max_length, min_length)) // 2
                    + 1 : (content_length + max(max_length, min_length)) // 2
                    - 1
                ]
                + ellipsis
            )
        elif after:
            content = content[: max(max_length - 1, min_length)] + ellipsis
        elif before:
            content = ellipsis + content[min(-max_length + 1, -min_length) :]
    return content


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
        display = "|{}{}{}|".format(before, match_type, after)

    return " " * index_start + format_text(display, STYLE["detector"]) + "\n"


def secrets_engine_version() -> str:
    return f"\nsecrets-engine-version: {VERSIONS.secrets_engine_version}\n"


def iac_engine_version(iac_engine_version: str) -> str:
    return f"\niac-engine-version: {iac_engine_version}\n"


def _file_info_decoration() -> str:
    """Returns the decoration to show at the beginning of the file_info line.

    The decoration can differ from one OS to the other.
    """
    return DECORATION_BY_OS.get(os.name, _file_info_default_decoration())


def _file_info_default_decoration() -> str:
    """Returns the header decoration to use if there is no OS-specific decoration"""
    return DECORATION_BY_OS["default"]


def file_info(filename: str, nb_secrets: int) -> str:
    """Return the formatted file info (number of secrets + filename)."""
    return "\n{} {} {} been found in file {}\n".format(
        _file_info_decoration(),
        format_text(str(nb_secrets), STYLE["nb_secrets"]),
        pluralize("incident has", nb_secrets, "incidents have"),
        format_text(filename, STYLE["filename"]),
    )


def no_leak_message() -> str:
    """
    Build a message if no secret is found.
    """
    return format_text("\nNo secrets have been found\n", STYLE["no_secret"])


def no_iac_vulnerabilities() -> str:
    """
    Build a message if no IaC vulnerabilities were found.
    """
    return format_text("\nNo incidents have been found\n", STYLE["no_secret"])


def get_lines_to_display(
    flat_matches_dict: Dict[int, List[Match]], lines: List, nb_lines: int
) -> Set[int]:
    """Retrieve the line indexes to display in the content with no secrets."""
    lines_to_display: Set[int] = set()

    for line in sorted(flat_matches_dict):
        for match in flat_matches_dict[line]:
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


def format_quota_color(remaining: int, limit: int) -> str:
    if limit == 0:
        return format_text(str(remaining), {"fg": "white"})

    available_percent = remaining / limit
    if available_percent < 0.25:
        color = "red"
    elif available_percent < 0.75:
        color = "yellow"
    else:
        color = "green"

    return format_text(str(remaining), {"fg": color})


def format_healthcheck_status(health_check: HealthCheckResponse) -> str:
    (color, status) = (
        ("red", f"unhealthy ({health_check.detail})")
        if health_check.status_code != 200
        else ("green", "healthy")
    )

    return format_text(status, {"fg": color})
