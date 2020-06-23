import os
from typing import Dict, List

import click
from pygitguardian.models import Match, PolicyBreak

from .filter import censor_content, leak_dictionary_by_ignore_sha
from .scannable import Result
from .text_utils import (
    STYLE,
    Line,
    format_line_count_break,
    format_text,
    get_offset,
    get_padding,
    pluralize,
)
from .utils import Filemode, get_lines_from_content, update_policy_break_matches


ICON_BY_OS = {"posix": "🛡️  ⚔️  🛡️ ", "default": ">>>"}

# MAX_SECRET_SIZE controls the max length of |-----| under a secret
# avoids occupying a lot of space in a CI terminal.
MAX_SECRET_SIZE = 80


def leak_message_located(
    flat_matches_dict: Dict[int, List[Match]],
    lines: List[Line],
    padding: int,
    offset: int,
    is_patch: bool,
    nb_lines: int = 2,
):
    """
    Return the formatted lines with a multiline secret.

    :param lines: The lines list
    :param line_index: The last index in the line
    :param detector_line: The list of detectors object in the line
    :param padding: The line padding
    :param offset: The offset due to the line display
    """

    # Line content
    def content(i: int) -> str:
        return lines[i].content

    lines_to_display = get_lines_to_display(flat_matches_dict, lines, nb_lines)

    old_line = None
    for line in sorted(lines_to_display):
        multiline_end = None
        if old_line and line - old_line != 1:
            click.echo(format_line_count_break(padding))
        if line in flat_matches_dict:
            click.echo(
                lines[line].build_line_count(padding, is_secret=True), nl=False,
            )
            index = 0
            for flat_match in sorted(
                flat_matches_dict[line], key=lambda x: x.index_start
            ):
                is_multiline = flat_match.line_start != flat_match.line_end
                click.echo(
                    f"{display_patch(content(line)[index:flat_match.index_start])}",
                    nl=False,
                )
                index = None if is_multiline else flat_match.index_end
                click.echo(
                    display_match_value(content(line)[flat_match.index_start : index]),
                    nl=False,
                )

                if is_multiline:
                    for match_line_index, match_line in enumerate(
                        flat_match.match.splitlines(False)[1:], 1
                    ):
                        click.echo()
                        click.echo(
                            lines[line + match_line_index].build_line_count(
                                padding, is_secret=True
                            ),
                            nl=False,
                        )
                        click.echo(display_match_value(match_line), nl=False)
                        multiline_end = line + match_line_index
                    index = flat_match.index_end

            click.echo(
                f"{display_patch(content(multiline_end if multiline_end else line)[index:])}"  # noqa
            )

            click.echo(
                display_detector(
                    add_detectors(flat_matches_dict[line], is_patch), offset,
                )
            )
        else:
            click.echo(
                lines[line].build_line_count(padding, is_secret=False), nl=False,
            )
            click.echo(f"{display_patch(content(line))}")
        old_line = multiline_end if multiline_end else line


def flatten_policy_breaks_by_line(
    policy_breaks: List[PolicyBreak],
) -> Dict[int, List[Match]]:
    """
    flatten_policy_breaks_by_line flatens a list of policy breaks with the
    same ignore SHA into a dict
    """
    flat_match_dict = dict()
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


def policy_break_header(
    issue_n: int, policy_breaks: List[PolicyBreak], ignore_sha: str
) -> str:
    return "\n{} Policy break {}({}): {} (Ignore with SHA: {}) ({} {})\n".format(
        format_text(">>>", STYLE["detector_line_start"]),
        issue_n,
        format_text(policy_breaks[0].policy, STYLE["detector"]),
        format_text(policy_breaks[0].break_type, STYLE["detector"]),
        format_text(ignore_sha, STYLE["ignore_sha"]),
        len(policy_breaks),
        pluralize("occurence", len(policy_breaks), "occurences"),
    )


def leak_message(result: Result, show_secrets: bool, nb_lines: int = 2):
    """
    Build readable message on the found policy breaks.

    :param result: The result from scanning API
    :param nb_lines: The number of lines to display before and after a secret in the
    patch
    :param show_secrets: Option to show secrets value
    :return: The formatted message to display
    """
    policy_breaks = result.scan.policy_breaks
    is_patch = result.filemode != Filemode.FILE
    sha_dict = leak_dictionary_by_ignore_sha(policy_breaks)

    if show_secrets:
        content = result.content
    else:
        content = censor_content(result.content, result.scan.policy_breaks)

    lines = get_lines_from_content(content, result.filemode, is_patch, show_secrets)
    padding = get_padding(lines)
    offset = get_offset(padding, is_patch)

    if len(lines) == 0:
        raise click.ClickException("Parsing of scan result failed.")

    click.echo(file_info(result.filename, len(sha_dict)))

    for issue_n, (ignore_sha, policy_breaks) in enumerate(sha_dict.items(), 1):
        click.echo(policy_break_header(issue_n, policy_breaks, ignore_sha))
        for policy_break in policy_breaks:
            update_policy_break_matches(policy_break.matches, lines, is_patch)

        if policy_breaks[0].policy == "Secrets detection":
            leak_message_located(
                flatten_policy_breaks_by_line(policy_breaks),
                lines,
                padding,
                offset,
                is_patch,
                nb_lines,
            )


def display_patch(patch: str) -> str:
    """ Return the formatted patch. """
    return format_text(patch, STYLE["patch"])


def display_match_value(match_value: str) -> str:
    """ Return the formatted match value. """
    return format_text(match_value, STYLE["secret"])


def display_detector(detector_line: List, offset: int) -> str:
    """ Return the formatted detector line. """
    return format_text(format_detector_line(detector_line, offset), STYLE["detector"])


def format_detector_line(detector_line: List, offset: int):
    """ Display detectors from detector_line. """
    message = " " * offset
    last_index = 0

    for detector in detector_line:
        spaces = detector["start_index"] - last_index
        # Overlay
        if spaces < 0:
            message += "\n"
            spaces = offset + detector["start_index"]

        message += "{}{}".format(" " * spaces, detector["display"])

        last_index = max(
            detector["end_index"], detector["start_index"] + len(detector["display"])
        )

    return message + "\n"


def add_detectors(flat_matches: List[Match], is_patch: bool) -> List[Dict]:
    return [add_detector(match, is_patch) for match in flat_matches]


def add_detector(match: Match, is_patch: bool) -> Dict:
    """ Return detector object to add in detector_line. """
    secret_lines = match.match.split("\n")
    detector_size = len(match.match_type)

    # Multiline secret
    if len(secret_lines) > 1:
        secret_size = max(
            match.index_start + len(secret_lines[0]),
            max((len(line) for line in secret_lines[1:-1]), default=0) - int(is_patch),
            match.index_end,
        )

    # Single line secret
    else:
        secret_size = len(secret_lines[0])

    display = ""
    if secret_size < MAX_SECRET_SIZE:
        before = "_" * max(1, int(((secret_size - detector_size) - 1) / 2))
        after = "_" * max(1, (secret_size - len(before) - detector_size) - 2)
        display = "|{}{}{}|".format(before, match.match_type, after)

    # Multiline
    if match.line_start != match.line_end:
        return {
            "display": display,
            "start_index": 0,
            "end_index": secret_size,
            "match": match,
        }

    return {
        "display": display,
        "start_index": match.index_start,
        "end_index": max(match.index_end, match.index_start + len(display)),
        "match": match,
    }


def file_info(filename: str, nb_secrets: int) -> str:
    """ Return the formatted file info (number of secrets + filename). """
    return "\n{} {} {} been found in file {}\n".format(
        ICON_BY_OS.get(os.name, ICON_BY_OS["default"]),
        format_text(str(nb_secrets), STYLE["nb_secrets"]),
        pluralize("policy break has", nb_secrets, "policy breaks have"),
        format_text(filename, STYLE["filename"]),
    )


def no_leak_message():
    """
    Build a message if no secret is found.

    :return: The formatted message to display
    """
    click.echo(format_text("No secrets have been found", STYLE["no_secret"]))


def get_lines_to_display(
    flat_matches_dict: Dict[int, List[Match]], lines: List, nb_lines: int
) -> List[str]:
    """ Retrieve the line indexes to display in the content with no secrets. """
    lines_to_display = set()

    for line in sorted(flat_matches_dict):
        for match in flat_matches_dict[line]:
            lines_to_display.update(
                range(match.line_start - nb_lines + 1, match.line_start + 1)
            )
            if match.line_end + 1 <= len(lines):
                lines_to_display.update(
                    range(
                        match.line_end + 1, min(match.line_end + nb_lines, len(lines))
                    )
                )

    return lines_to_display
