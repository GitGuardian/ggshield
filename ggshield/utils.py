import re
from enum import Enum
from typing import List

from pygitguardian.models import Match

from .text_utils import Line, LineCategory


# max file size to accept
MAX_FILE_SIZE = 1048576

REGEX_PATCH_HEADER = re.compile(
    r"^(?P<line_content>@@ -(?P<pre_index>\d+),?\d* \+(?P<post_index>\d+),?\d* @@(?: .+)?)"  # noqa
)


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
    PERMISSION_CHANGE = (7, "changed permissions")
    FILE = (0, "file")

    def __init__(self, start, mode):
        self.start = start
        self.mode = mode


def get_lines_from_content(
    content: str, filemode: Filemode, is_patch: bool, show_secrets: bool
) -> List[str]:
    """
    Return the secrets and the lines with line number.

    :param scan_result: Scan result from the API call
    :param show_secrets: Option to hide secrets value
    :param is_patch: Is the content a patch
    """

    # Patch
    if is_patch:
        return list(get_lines_from_patch(content, filemode))

    # File
    return list(get_lines_from_file(content))


def get_lines_from_file(content: str) -> List:
    """ Return the lines with line number from a file. """
    for line_count, line_content in enumerate(content.split("\n")):
        yield Line(
            content=line_content, category=LineCategory.data, pre_index=line_count + 1
        )


def get_lines_from_patch(content: str, filemode: Filemode) -> List:
    """ Return the lines with line number from a git patch. """
    content += "\n"
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
            m = REGEX_PATCH_HEADER.search(line)
            pre_index = m.groupdict()["pre_index"]
            post_index = m.groupdict()["post_index"]
            line_content = m.groupdict()["line_content"][:-1]

            if filemode == Filemode.NEW or filemode == Filemode.DELETE:
                pre_index = 1
                post_index = 1

            else:
                pre_index = int(pre_index)
                post_index = int(post_index)

            if line_content:
                line_type = " "
                pre_index -= 1
                post_index -= 1
                line_pre_index = None
                line_post_index = None
                category = LineCategory.empty

        elif line_type == "+":
            post_index += 1
            line_post_index = post_index
            line_content = line[1:]
            category = LineCategory.addition

        elif line_type == "-":
            pre_index += 1
            line_pre_index = pre_index
            line_content = line[1:]
            category = LineCategory.deletion

        if line_type and line_content is not None:
            yield Line(
                content=line_content,
                category=category,
                pre_index=line_pre_index,
                post_index=line_post_index,
            )


def update_policy_break_matches(
    matches: List[Match], lines: List[Line], is_patch: bool
):
    """
    Update secrets object with secret line and indexes in line.

    :param secrets: List of secrets sorted by start index
    :param lines: List of content lines with indexes (post_index and pre_index)
    :param is_patch: True if is patch from git, False if file
    """
    index = 0
    line_index = 0

    for match in matches:
        if not match.index_start:
            continue
        len_line = len(lines[line_index].content) + 1 + int(is_patch)
        # Update line_index until we find the secret start
        while match.index_start >= index + len_line:
            index += len_line
            line_index += 1
            len_line = len(lines[line_index].content) + 1 + int(is_patch)

        start_line = line_index
        start_index = match.index_start - index - int(is_patch)

        # Update line_index until we find the secret end
        while match.index_end > index + len_line:
            index += len_line
            line_index += 1
            len_line = len(lines[line_index].content) + 1 + int(is_patch)

        match.index_start = start_index
        match.index_end = match.index_end - index - int(is_patch) + 1
        match.line_start = start_line
        match.line_end = line_index
