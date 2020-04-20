import os
from typing import Dict, List, Union

import click

from .utils import Filemode, process_scan_to_secrets_and_lines


STYLE = {
    "nb_secrets": {"fg": "bright_blue", "bold": True},
    "filename": {"fg": "bright_yellow", "bold": True},
    "patch": {"fg": "white"},
    "secret": {"fg": "bright_red"},
    "error": {"fg": "red"},
    "no_secret": {"fg": "white"},
    "detector": {"fg": "bright_white", "bold": True},
    "line_count": {"fg": "white", "dim": True},
    "line_count_secret": {"fg": "yellow"},
}

LINE_DISPLAY = {"file": "{} | ", "patch": "{} {} | "}

ICON_BY_OS = {"posix": "🛡️  ⚔️  🛡️ ", "default": ">>>"}


def leak_message(
    scan_result: Dict, nb_lines: int = 3, hide_secrets: bool = True
) -> str:
    """
    Build readable message on the found secrets.

    :param scan_result: The result from scanning API
    :param nb_lines: The number of line to display before and after a secret in the
    patch
    :param hide_secrets: Option to hide secrets value
    :return: The formatted message to display
    """

    filename = scan_result["filename"]
    filemode = scan_result["filemode"]
    is_patch = filemode != Filemode.FILE
    secrets, lines = process_scan_to_secrets_and_lines(scan_result, hide_secrets)
    lines_to_display = get_lines_to_display(secrets, lines, nb_lines)
    padding = get_padding(lines, is_patch)
    offset = get_offset(padding, is_patch)

    if len(secrets) == 0 or len(lines) == 0:
        raise click.ClickException("Parsing of scan result failed.")

    message = file_info(filename, len(secrets))

    line_count = 0
    line_index = 0
    detector_line = []

    # Line content
    def content(i: int) -> str:
        return lines[i]["content"]

    for i, secret in enumerate(secrets):
        # New line with secrets
        if secret["start_line"] != line_count:
            if i > 0:
                # Add the end of patch of the previous line with a secret
                message += "{}\n{}".format(
                    display_patch(content(line_count)[secrets[i - 1]["end_index"] :]),
                    display_detector(detector_line, offset),
                )
                detector_line = []

            line_count = secret["start_line"]
            line_index = 0

            # Display backward context
            while len(lines_to_display) and lines_to_display[0] < line_count:
                index = lines_to_display.pop(0)
                message += "{}{}\n".format(
                    display_line_count(lines[index], padding),
                    display_patch(content(index)),
                )

            message += display_line_count(lines[line_count], padding, is_secret=True)

        # One line secret
        if line_count == secret["end_line"]:
            message += display_one_line_secret(secret, lines, line_index)

        # Multiline secret
        else:
            message += display_multiline_secret(
                secret, lines, line_index, detector_line, padding, offset
            )
            detector_line = []

        detector_line.append(add_detector(secret, is_patch))
        line_count = secret["end_line"]
        line_index = secret["end_index"]

    message += "{}\n{}".format(
        display_patch(content(line_count)[secret["end_index"] :]),
        display_detector(detector_line, offset),
    )

    # Display forward context
    while len(lines_to_display):
        index = lines_to_display.pop(0)
        message += "{}{}\n".format(
            display_line_count(lines[index], padding), display_patch(content(index))
        )

    return message


def display_one_line_secret(secret: object, lines: List, line_index: int) -> str:
    """
    Return the formatted oneline secret.

    :param secret: The secret object to display
    :param lines: The lines list
    :param line_index: The last index in the line
    """

    # Line content
    def content() -> str:
        return lines[line_count]["content"]

    line_count = secret["start_line"]

    return "{}{}".format(
        display_patch(content()[line_index : secret["start_index"]]),
        display_secret(content()[secret["start_index"] : secret["end_index"]]),
    )


def display_multiline_secret(
    secret: object,
    lines: List,
    line_index: int,
    detector_line: List,
    padding: int,
    offset: int,
) -> str:
    """
    Return the formatted lines with a multiline secret.

    :param secret: The secret object to display
    :param lines: The lines list
    :param line_index: The last index in the line
    :param detector_line: The list of detectors object in the line
    :param padding: The line padding
    :param offset: The offset due to the line display
    """

    # Line content
    def content() -> str:
        return lines[line_count]["content"]

    line_count = secret["start_line"]

    # Display first line of multiline secret
    message = "{}{}\n".format(
        display_patch(content()[line_index : secret["start_index"]]),
        display_secret(content()[secret["start_index"] :]),
    )

    # Display detectors from potential other secrets in the first line
    if len(detector_line):
        message += display_detector(detector_line, offset)

    # Iter over secret lines
    for line_count in range(secret["start_line"] + 1, secret["end_line"]):
        message += "{}{}\n".format(
            display_line_count(lines[line_count], padding, is_secret=True),
            display_secret(content()),
        )

    # Display last line
    line_count += 1
    message += "{}{}".format(
        display_line_count(lines[line_count], padding, is_secret=True),
        display_secret(content()[: secret["end_index"]]),
    )

    return message


def display_patch(patch: str) -> str:
    """ Return the formatted patch. """
    return format_text(patch, STYLE["patch"])


def display_secret(secret: str) -> str:
    """ Return the formatted secret. """
    return format_text(secret, STYLE["secret"])


def display_detector(detector_line: List, offset: int) -> str:
    """ Return the formatted detector line. """
    return format_text(format_detector_line(detector_line, offset), STYLE["detector"])


def display_line_count(line: object, padding: int, is_secret: bool = False) -> str:
    """ Return the formatted line count. """
    line_count_style = STYLE["line_count_secret"] if is_secret else STYLE["line_count"]

    # File
    if line.get("index"):
        return LINE_DISPLAY["file"].format(
            format_text(fomat_line_count(line["index"], padding), line_count_style)
        )

    # Patch
    else:
        pre_index = fomat_line_count(line["pre_index"], padding)
        post_index = fomat_line_count(line["post_index"], padding)

        if line["type"] == "+":
            pre_index = " " * padding

        elif line["type"] == "-":
            post_index = " " * padding

        return LINE_DISPLAY["patch"].format(
            format_text(pre_index, line_count_style),
            format_text(post_index, line_count_style),
        )


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

    return message + "\n\n"


def add_detector(secret: object, is_patch: bool) -> object:
    """ Return detector object to add in detector_line. """
    secret_lines = secret["value"].split("\n")
    detector_size = len(secret["detector"])

    # Multiline secret
    if len(secret_lines) > 1:
        secret_size = max(
            secret["start_index"] + len(secret_lines[0]),
            max([len(line) for line in secret_lines[1:-1]]) - int(is_patch),
            secret["end_index"],
        )

    # Single line secret
    else:
        secret_size = len(secret_lines[0])

    before = "_" * max(1, int(((secret_size - detector_size) - 1) / 2))
    after = "_" * max(1, (secret_size - len(before) - detector_size) - 2)
    display = "|{}{}{}|".format(before, secret["detector"], after)

    # Multiline
    if secret["start_line"] != secret["end_line"]:
        return {"display": display, "start_index": 0, "end_index": secret_size}

    return {
        "display": display,
        "start_index": secret["start_index"],
        "end_index": max(secret["end_index"], secret["start_index"] + len(display)),
    }


def get_lines_to_display(secrets: List, lines: List, nb_lines: int) -> List:
    """ Retrieve the line indexes to display in the content with no secrets. """
    lines_to_display = set()

    for secret in secrets:
        for index in set(range(len(lines))).intersection(
            range(secret["start_line"] - nb_lines, secret["end_line"] + 1 + nb_lines)
        ):
            lines_to_display.add(index)

    for secret in secrets:
        for index in range(secret["start_line"], secret["end_line"] + 1):
            lines_to_display.discard(index)

    return sorted(list(lines_to_display))


def fomat_line_count(line_count: Union[int, None], padding: str) -> str:
    """ Return the padded line count. """
    if line_count is None:
        return " " * padding

    return " " * max(0, padding - len(str(line_count))) + str(line_count)


def get_padding(lines: List, is_patch: bool = False) -> int:
    """ Return the number of digit of the maximum line number. """
    # value can be None
    if is_patch:
        return max(
            len(str(lines[-1]["pre_index"] or 0)),
            len(str(lines[-1]["post_index"] or 0)),
        )

    return len(str(lines[-1]["index"]))


def get_offset(padding: int, is_patch: bool = False) -> int:
    """ Return the offset due to the line display. """
    if is_patch:
        return len(LINE_DISPLAY["patch"].format("0" * padding, "0" * padding))

    return len(LINE_DISPLAY["file"].format("0" * padding))


def pluralize(name: str, nb: int, plural: Union[str, None] = None) -> str:
    if nb == 1:
        return name
    return plural or (name + "s")


def file_info(filename: str, nb_secrets: int) -> str:
    """ Return the formatted file info (number of secrets + filename). """
    return "\n{} {} {} been found in file {}\n\n".format(
        ICON_BY_OS.get(os.name, ICON_BY_OS["default"]),
        format_text(str(nb_secrets), STYLE["nb_secrets"]),
        pluralize("secret has", nb_secrets, "secrets have"),
        format_text(filename, STYLE["filename"]),
    )


def format_text(text: str, style: str) -> str:
    """ Return the formatted text with the given style. """
    return click.style(
        text, fg=style["fg"], bold=style.get("bold", False), dim=style.get("dim", False)
    )


def error_message(error: str) -> str:
    """
    Build a message in case of error.

    :return: The formatted message to display
    """
    return "{} : {}".format(format_text("Error", STYLE["error"]), error)


def no_leak_message() -> str:
    """
    Build a message if no secret is found.

    :return: The formatted message to display
    """
    return format_text("No secrets have been found", STYLE["no_secret"])


def process_scan_result(
    results: List, nb_lines: int = 3, hide_secrets: bool = True, verbose: bool = True
) -> int:
    """
    Process a commit scan result.

    :param results: The results from scanning API
    :param nb_lines: The number of lines to display before and after a secret in the
    patch
    :param hide_secrets: Hide secrets value
    :param verbose: Display message even if there is no secrets
    :return: The exit code
    """
    leak = False
    error = False

    for scan_result in results:
        if scan_result.get("error", False):
            click.echo(error_message(scan_result["error"]))
            error = True
        elif scan_result.get("has_leak", False):
            click.echo(leak_message(scan_result, nb_lines, hide_secrets))
            leak = True

    if leak or error:
        return 1

    if verbose:
        click.echo(no_leak_message())

    return 0
