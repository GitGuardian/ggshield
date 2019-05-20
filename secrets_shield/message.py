from typing import Dict, List, Union

# Console colors
RED = "\u001b[31m"
YELLOW_BRIGHT = "\u001b[33;1m"
BLUE_BRIGHT = "\u001b[34;1m"
WHITE_DIM = "\u001b[2m"
RESET_STYLE = "\u001b[0m"

STYLE = {
    "nb_secrets": BLUE_BRIGHT,
    "filename": YELLOW_BRIGHT,
    "patch": WHITE_DIM,
    "secret": RED,
    "error": RED,
    "no_secret": WHITE_DIM,
}


def leak_message(scan_result: Dict, nb_lines: int = 3) -> str:
    """
    Build readable message on the found secrets.
    :param scan_result: The result from scanning API
    :param nb_lines: The number of line to display before and after a secret in the patch
    :return: The formatted message to display
    """

    filename = scan_result["filename"]
    content = scan_result["content"]
    secrets = flatten_secrets(scan_result)

    message = file_info(filename, len(secrets))
    index = 0
    detector_line = ""

    for i, secret in enumerate(secrets):
        start = secret["start"]
        end = secret["end"]

        # Checks if there is a '\n' between 2 secrets
        # If so, we need to add the detector_line before processing the next line
        if content.find("\n", index, start) != -1:
            message += format_detector(content, index, detector_line)
            index += len(forward_context(content, index, 1))
            detector_line = ""

        if i == 0:
            message += format_text(
                backward_context(content, start, nb_lines), STYLE["patch"]
            )
        else:
            # Skips some of the patch if there is too much text between 2 secrets
            if lines_between(content, index, start) > 2 * nb_lines:
                message += format_secret_separation(content, index, start, nb_lines)

            # Otherwise we display the patch between the previous_secret and the curent one
            else:
                message += format_text(content[index:start], STYLE["patch"])

        # We compute the secret offset in current line for detector_line
        offset = len(backward_context(content, secret["start"], 1))
        message += format_text(secret["value"], STYLE["secret"])

        # We update the detector_line to add the current secret detector
        detector_line = update_detector_line(secret, offset, detector_line)

        # Update index for next secret
        index = end

    if detector_line != "":
        message += format_detector(content, index, detector_line)
        index += len(forward_context(content, index, 1))

    message += format_text(forward_context(content, index, nb_lines), STYLE["patch"])

    return message


def flatten_secrets(result: Dict) -> List:
    """
    Select one secret by string matched in the Scanning API result.
    """
    secrets = []

    for secret in result["scan"]["secrets"]:
        for match in secret["matches"]:
            display_name = secret["detector"]["display_name"]
            value = match["string_matched"]

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


def pluralize(name: str, nb: int, plural: str = None) -> str:
    if nb == 1:
        return name
    return plural or (name + "s")


def file_info(filename: str, nb_secrets: int) -> str:
    return "\n🛡️  ⚔️  🛡️  {} {} been found in file {}\n".format(
        format_text(str(nb_secrets), STYLE["nb_secrets"]),
        pluralize("secret has", nb_secrets, "secrets have"),
        format_text(filename, STYLE["filename"]),
    )


def lines_between(content: str, start: int, end: int) -> int:
    return len(content[start:end].split("\n"))


def format_text(text: str, style: Union[List, str]) -> str:
    if type(style) is list:
        return "".join(style) + text + RESET_STYLE

    return style + text + RESET_STYLE


def update_detector_line(secret: Dict, offset: int, detector_line: str) -> str:
    """
    Update detector_line by adding a new detector with formatting.

    Example:
    +github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91
                   |_____________GitHub Token_____________|

    :param secret: A secret object
    :param offset: Offset in current line
    :param detector_line: The line to update with the new detector name
    :return: The updated detector line
    """
    secret_size = len(secret["value"])
    detector_size = len(secret["detector"])

    before = "_" * max(1, int(((secret_size - detector_size) - 1) / 2))
    after = "_" * max(1, (secret_size - len(before) - detector_size) - 2)

    # If the size of the previous detector name is too long, we add a new line
    if len(detector_line) > offset:
        return detector_line + "\n{}|{}{}{}|".format(
            " " * offset, before, secret["detector"], after
        )

    return detector_line + "{}|{}{}{}|".format(
        " " * (offset - len(detector_line)), before, secret["detector"], after
    )


def format_detector(content: str, index: int, detector_line: str) -> str:
    """
    Adds a line with the detector names of the secrets on the previous line.
    :param content: The content of the file
    :param index: The index of the end of the last secret detected
    :param detector_line: A string containing the detector names
    :return : The formatted string
    """
    return (
        format_text(forward_context(content, index, 1), STYLE["patch"])
        + "\n"
        + detector_line
        + "\n"
    )


def format_secret_separation(
    content: str, last_end: int, start: int, nb_lines: int
) -> str:
    """
    Format the patch to skip the content of two consecutive secrets that are too far from one another
    :param content: The content of the file
    :param last_end: The index of the end of the previous secret
    :param start: The index of the start of the current index
    :param nb_lines: The number of lines we want to keep around each secret
    :return : The formatted string
    """
    return (
        format_text(forward_context(content, last_end, nb_lines), STYLE["patch"])
        + "\n\n"
        + format_text(backward_context(content, start, nb_lines), STYLE["patch"])
    )


def backward_context(content: str, index: int, nb_lines: int) -> str:
    return "\n".join(content[:index].split("\n")[-nb_lines:])


def forward_context(content: str, index: int, nb_lines: int) -> str:
    return "\n".join(content[index:].split("\n")[:nb_lines])


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


def process_scan_result(results: List, nb_lines: int = 3) -> int:
    """
    Process a commit scan result.
    :return: The exit code
    """
    leak = False
    error = False

    for scan_result in results:
        if scan_result["error"]:
            print(error_message(scan_result["scan"]["error"]))
            error = True
        elif scan_result["has_leak"]:
            print(leak_message(scan_result, nb_lines))
            leak = True

    if leak or error:
        return 1

    print(no_leak_message())
    return 0
