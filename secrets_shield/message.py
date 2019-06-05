import click
from typing import Dict, List, Set, Union

from secrets_shield.utils import process_scan_lines, Filemode

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


def leak_message(
    scan_result: Dict, nb_lines: int = 3, hide_secrets: bool = False
) -> str:
    """
    Build readable message on the found secrets.

    :param scan_result: The result from scanning API
    :param nb_lines: The number of line to display before and after a secret in the patch
    :param hide_secrets: Option to hide secrets value
    :return: The formatted message to display
    """

    filename = scan_result["filename"]
    filemode = scan_result["filemode"]
    content = scan_result["content"]
    secrets = flatten_secrets(scan_result, hide_secrets)
    lines = process_scan_lines(content, secrets, filemode)

    if len(lines) == 0:
        raise click.ClickException("Parsing of scan result failed.")

    message = file_info(filename, len(secrets))
    padding = get_padding(lines)

    for index in lines_to_display(lines, nb_lines):
        message += format_line(lines[index], padding, filemode == Filemode.FILE) + "\n"

    return message


def lines_to_display(lines: List, nb_lines: int) -> Set:
    """ Retrieve the line indexes to display in the content. """
    line_index_to_display = set()

    for index, line in enumerate(lines):
        if len(line["secrets"]):
            # We intersect the index range with the secret line index +/- nb_lines
            for i in set(range(len(lines))).intersection(
                range(index - nb_lines, index + nb_lines + 1)
            ):
                line_index_to_display.add(i)

    return line_index_to_display


def format_line(line: object, padding: int, is_file: bool = False) -> str:
    """ Return the line with formatting of the secrets. """
    content = line["content"]
    secrets = line["secrets"]
    last_index = 0

    line_count_style = (
        STYLE["line_count_secret"] if len(secrets) else STYLE["line_count"]
    )

    if is_file:
        # Offset due to the line count display
        offset = padding + 3

        line_to_display = "{} | ".format(
            format_text(fomat_line_count(line["index"], padding), line_count_style)
        )

    else:
        pre_index = fomat_line_count(line["pre_index"], padding)
        post_index = fomat_line_count(line["post_index"], padding)

        if line["type"] == "+":
            pre_index = " " * padding

        elif line["type"] == "-":
            post_index = " " * padding

        # Offset due to the line count display
        offset = 2 * (padding + 2)

        line_to_display = "{} {} | ".format(
            format_text(pre_index, line_count_style),
            format_text(post_index, line_count_style),
        )

    for secret in secrets:
        # For each secret, we add the content between the end of the previous secret
        # and the current formatted secret
        line_to_display += format_text(
            content[last_index : secret["start"]], STYLE["patch"]
        )
        line_to_display += format_text(secret["value"], STYLE["secret"])
        last_index = secret["end"]

    # Finally we add the remaining content
    line_to_display += format_text(content[last_index:], STYLE["patch"])

    # If there are secrets in this line, we add a new line with the detector name after it
    if len(secrets):
        line_to_display += format_detector(secrets, padding, offset)

    return line_to_display


def format_detector(secrets: List, padding: int, offset: int) -> str:
    """
    Return the formatted line(s) containing the detector name(s).

    :param secrets: The list of secrets object for the current line
    :param padding: The size of the padding
    :param offset: The offset due to the line count display
    """
    last_index = 0
    detector_line = "\n" + " " * offset

    for secret in secrets:
        secret_size = len(secret["value"])
        detector_size = len(secret["detector"])

        before = "_" * max(1, int(((secret_size - detector_size) - 1) / 2))
        after = "_" * max(1, (secret_size - len(before) - detector_size) - 2)

        # If the size of the previous detector name is too long, we add a new line
        if last_index > secret["start"]:
            detector_line += "\n{}|{}{}{}|".format(
                " " * secret["start"], before, secret["detector"], after
            )

        else:
            detector_line += "{}|{}{}{}|".format(
                " " * (secret["start"] - last_index), before, secret["detector"], after
            )

        last_index = max(secret["end"], secret["start"] + detector_size + 4)

    return detector_line + "\n"


def flatten_secrets(result: Dict, hide_secrets: bool) -> List:
    """ Select one secret by string matched in the Scanning API result. """
    secrets = []

    for secret in result["scan"]["secrets"]:
        for match in secret["matches"]:
            display_name = secret["detector"]["display_name"]
            value = (
                match["string_matched"]
                if not hide_secrets
                else match["string_matched"][:4]
                + "*" * max(0, (len(match["string_matched"]) - 4))
            )

            secrets.append(
                {
                    "detector": display_name,
                    "value": value,
                    "start": match["indice_start"],
                    "end": match["indice_end"],
                }
            )

    # We get the first detector for each start index
    secrets = list({s["start"]: s for s in secrets[::-1]}.values())
    secrets = sorted(secrets, key=lambda x: x["start"])

    return secrets


def fomat_line_count(line_count: Union[int, None], padding: str) -> str:
    """ Return the padded line count. """
    if line_count is None:
        return " " * padding

    return " " * max(0, padding - len(str(line_count))) + str(line_count)


def get_padding(lines: List) -> int:
    """ Return the number of digit of the maximum line number. """
    if lines[-1].get("index"):
        return len(str(lines[-1]["index"]))

    # value can be None
    return max(
        len(str(lines[-1]["pre_index"] or 0)), len(str(lines[-1]["post_index"] or 0))
    )


def pluralize(name: str, nb: int, plural: Union[str, None] = None) -> str:
    if nb == 1:
        return name
    return plural or (name + "s")


def file_info(filename: str, nb_secrets: int) -> str:
    """ Return the formatted file info (number of secrets + filename). """
    return "\n🛡️  ⚔️  🛡️  {} {} been found in file {}\n\n".format(
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
    results: List, nb_lines: int = 3, hide_secrets: bool = False, verbose: bool = True
) -> int:
    """
    Process a commit scan result.

    :param results: The results from scanning API
    :param nb_lines: The number of lines to display before and after a secret in the patch
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
