import os
from io import StringIO
from typing import Dict, List, Optional, Set

from pygitguardian.models import Match, PolicyBreak

from ggshield.text_utils import STYLE, Line, format_text, pluralize


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
    nb_lines: int,
) -> str:
    """
    Display leak message of a policy break with location in content.

    :param lines: The lines list
    :param line_index: The last index in the line
    :param detector_line: The list of detectors object in the line
    :param padding: The line padding
    :param offset: The offset due to the line display
    """
    leak_msg = StringIO()

    # Line content
    def content(i: int) -> str:
        return lines[i].content

    lines_to_display = get_lines_to_display(flat_matches_dict, lines, nb_lines)

    old_line: Optional[int] = None
    for line in sorted(lines_to_display):
        multiline_end = None
        if old_line is not None and line - old_line != 1:
            leak_msg.write(format_line_count_break(padding))
        if line in flat_matches_dict:
            leak_msg.write(lines[line].build_line_count(padding, is_secret=True))
            index: Optional[int] = 0
            for flat_match in sorted(
                flat_matches_dict[line], key=lambda x: x.index_start  # type: ignore
            ):
                is_multiline = flat_match.line_start != flat_match.line_end
                leak_msg.write(
                    f"{display_patch(content(line)[index:flat_match.index_start])}",
                )
                index = None if is_multiline else flat_match.index_end
                leak_msg.write(
                    display_match_value(content(line)[flat_match.index_start : index]),
                )

                if is_multiline:
                    for match_line_index, match_line in enumerate(
                        flat_match.match.splitlines(False)[1:], 1
                    ):
                        leak_msg.write("\n")
                        leak_msg.write(
                            lines[line + match_line_index].build_line_count(
                                padding, is_secret=True
                            ),
                        )
                        leak_msg.write(display_match_value(match_line))
                        multiline_end = line + match_line_index
                    index = flat_match.index_end

            leak_msg.write(
                f"{display_patch(content(multiline_end if multiline_end else line)[index:])}\n"  # noqa
            )

            leak_msg.write(
                display_detector(
                    add_detectors(flat_matches_dict[line], is_patch),
                    offset,
                )
            )
        else:
            leak_msg.write(lines[line].build_line_count(padding, is_secret=False))
            leak_msg.write(f"{display_patch(content(line))}\n")
        old_line = multiline_end if multiline_end else line

    return leak_msg.getvalue()


def flatten_policy_breaks_by_line(
    policy_breaks: List[PolicyBreak],
) -> Dict[int, List[Match]]:
    """
    flatten_policy_breaks_by_line flatens a list of policy breaks with the
    same ignore SHA into a dict
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


def display_patch(patch: str) -> str:
    """ Return the formatted patch. """
    return format_text(patch, STYLE["patch"])


def display_match_value(match_value: str) -> str:
    """ Return the formatted match value. """
    return format_text(match_value, STYLE["secret"])


def display_detector(detector_line: List, offset: int) -> str:
    """ Return the formatted detector line. """
    return format_text(format_detector_line(detector_line, offset), STYLE["detector"])


def format_detector_line(detector_line: List, offset: int) -> str:
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


def no_leak_message() -> str:
    """
    Build a message if no secret is found.
    """
    return format_text("No secrets have been found\n", STYLE["no_secret"])


def get_lines_to_display(
    flat_matches_dict: Dict[int, List[Match]], lines: List, nb_lines: int
) -> Set[int]:
    """ Retrieve the line indexes to display in the content with no secrets. """
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
