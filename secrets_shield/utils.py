import re
import subprocess

from enum import Enum
from typing import List


class Filemode(Enum):
    """
    Enum class for git filemode.

    Attributes:
        start (int): The first line to read in this filemode scenario
        mode  (str): The string filemode
    """

    MODIFY = (4, "modified file")
    DELETE = (5, "deleted file")
    NEW = (5, "new file")
    RENAME = (7, "renamed file")
    FILE = (0, "file")

    def __init__(self, start, mode):
        self.start = start
        self.mode = mode


def shell(command: str) -> List:
    """ Execute a command in a subprocess. """
    return (
        subprocess.check_output(command.split(" ")).decode("utf-8").rstrip().split("\n")
    )


def process_scan_lines(content: str, secrets: List, filemode: Filemode) -> List:
    """
    Return the lines with line number and secrets.

    :param content: Content of the git patch
    :param secrets: List of secrets in the patch
    :param filemode: File mode [file|new|delete|rename|modify]
    """
    if filemode == Filemode.FILE:
        return _get_lines_from_file(content, secrets)

    return _get_lines_from_patch(content, secrets, filemode)


def _get_line_secrets(
    line_content: str, secrets: List, index: int, is_patch: bool = False
) -> (List, int):
    """
    Return secret list in the line with updated index.

    :param line_content: Content of the line
    :param secrets: List of secrets in the line
    :param is_patch: True if line_content comes from a git patch

    :return: The updated secrets list and secret index
    """
    line_secrets = []

    for secret in secrets:
        # Add 1 for the leading +/- in a git line (0 if not git patch)
        if secret["start"] < index + len(line_content) + int(is_patch):
            start = line_content.index(secret["value"])
            end = start + len(secret["value"])
            line_secrets.append(dict(secret, **{"start": start, "end": end}))
        else:
            break

    return line_secrets


def _get_lines_from_file(content: str, secrets: List) -> List:
    """
    Return the lines with line number and secrets from a file.

    :param content: Content of the file
    :param secrets:  Secret list in this file
    """
    lines = []
    index = 0

    for line_count, line_content in enumerate(content.split("\n")):
        line_secrets = _get_line_secrets(line_content, secrets, index)
        secrets = secrets[len(line_secrets) :]

        lines.append(
            {"index": line_count + 1, "content": line_content, "secrets": line_secrets}
        )

        index += len(line_content) + 1

    return lines


def _get_lines_from_patch(content: str, secrets: List, filemode: str) -> List:
    """
    Return the lines with line number and secrets from a git patch.

    :param content: Content of the git patch
    :param secrets: List of secrets in the patch
    :param filemode: File mode [new|delete|rename|modify]
    """
    # Make sure there is a trailing new line
    content += "\n"
    lines = []
    index = 0

    pre_index = 0
    post_index = 0

    for line in content.split("\n"):
        line_type = line[:1]
        line_content = ""
        line_pre_index = None
        line_post_index = None

        if line_type == " ":
            line_content = line[1:]
            pre_index += 1
            post_index += 1
            line_pre_index = pre_index
            line_post_index = post_index

        elif line_type == "@":
            REGEX_PATCH_HEADER = r"@@ -(?P<pre_index>\d+),?\d* \+(?P<post_index>\d+),?\d* @@(?: (?P<line_content>.+))?"
            m = re.search(REGEX_PATCH_HEADER, line)
            pre_index = m.groupdict()["pre_index"]
            post_index = m.groupdict()["post_index"]
            line_content = m.groupdict()["line_content"]

            if filemode == Filemode.NEW.mode or filemode == Filemode.DELETE.mode:
                pre_index = 0
                post_index = 0

            else:
                pre_index = int(pre_index)
                post_index = int(post_index)

            if line_content:
                line_type = " "
                pre_index -= 1
                post_index -= 1
                line_pre_index = pre_index
                line_post_index = post_index

        elif line_type == "+":
            post_index += 1
            line_post_index = post_index
            line_content = line[1:]

        elif line_type == "-":
            pre_index += 1
            line_pre_index = pre_index
            line_content = line[1:]

        if line_type and line_content is not None:
            line_secrets = _get_line_secrets(
                line_content, secrets, index, is_patch=True
            )
            # We update the secrets remaining, as they are sorted by index
            secrets = secrets[len(line_secrets) :]

            lines.append(
                add_line(
                    line_type,
                    line_pre_index,
                    line_post_index,
                    line_content,
                    line_secrets,
                )
            )

        # Add 1 for the \n
        index += len(line) + 1

    return lines


def add_line(
    line_type: str,
    pre_index: int,
    post_index: int,
    line_content: str,
    line_secrets: List,
):
    """
    Return the new line object to add.

    :param line_type: The line type [+|-| ]
    :param pre_index: Line index (deletion)
    :param post_index: Line index (addition)
    :param line_content: Content of the line
    :param line_secrets: List of secrets in the line
    """
    return {
        "type": line_type,
        "pre_index": pre_index,
        "post_index": post_index,
        "content": line_content,
        "secrets": line_secrets,
    }
