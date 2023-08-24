import re
from enum import Enum, auto
from typing import Iterable, List, NamedTuple, Optional

from ggshield.core.text_utils import STYLE, format_line_count, format_text
from ggshield.utils.git_shell import Filemode


REGEX_PATCH_HEADER = re.compile(
    r"^(?P<line_content>@@ -(?P<pre_index>\d+),?\d* \+(?P<post_index>\d+),?\d* @@(?: .+)?)"  # noqa
)

# Prefix used before each line for a complete file
FILE_LINE_PREFIX = "{} | "

# Prefix used before each line for a patch
PATCH_LINE_PREFIX = "{} {} | "


class LineCategory(Enum):
    addition = auto()
    data = auto()
    deletion = auto()
    empty = auto()


class Line(NamedTuple):
    """
    Line object making easier to handle line
    by line display.

    - content: Content of the line
    - category: The line category [+|-| ] (addition, deletion, untouched)
    - pre_index: Line index (deletion for patches, line index for files)
    - post_index: Line index (addition for patches)
    """

    content: str
    category: Optional[LineCategory] = None
    pre_index: Optional[int] = None
    post_index: Optional[int] = None

    def build_line_count(self, padding: int, is_secret: bool = False) -> str:
        """Return the formatted line count."""
        line_count_style = (
            STYLE["line_count_secret"] if is_secret else STYLE["line_count"]
        )
        if self.category is not None and not isinstance(self.category, LineCategory):
            raise TypeError("line category invalid")

        # File
        if self.category == LineCategory.data:
            return FILE_LINE_PREFIX.format(
                format_text(
                    format_line_count(self.pre_index, padding), line_count_style
                )
            )

        # Patch
        pre_index = format_line_count(self.pre_index, padding)
        post_index = format_line_count(self.post_index, padding)

        if self.category == LineCategory.addition:
            pre_index = " " * padding

        elif self.category == LineCategory.deletion:
            post_index = " " * padding

        return PATCH_LINE_PREFIX.format(
            format_text(pre_index, line_count_style),
            format_text(post_index, line_count_style),
        )


def get_lines_from_content(
    content: str, filemode: Filemode, is_patch: bool
) -> List[Line]:
    """
    Return the secrets and the lines with line number.

    :param content: Content to scan
    :param filemode: Filemode of the content
    :param is_patch: Is the content a patch
    """

    # Patch
    if is_patch:
        return list(get_lines_from_patch(content, filemode))

    # File
    return list(get_lines_from_file(content))


def get_lines_from_file(content: str) -> Iterable[Line]:
    """Return the lines with line number from a file."""
    for line_count, line_content in enumerate(content.split("\n")):
        yield Line(
            content=line_content, category=LineCategory.data, pre_index=line_count + 1
        )


def get_lines_from_patch(content: str, filemode: Filemode) -> Iterable[Line]:
    """Return the lines with line number from a git patch."""
    content += "\n"
    pre_index = 0
    post_index = 0

    for line in content.split("\n"):
        line_type = line[:1]
        line_content = ""
        line_pre_index = None
        line_post_index = None
        category = None

        if line_type == " ":
            line_content = line[1:]
            pre_index += 1
            post_index += 1
            line_pre_index = pre_index
            line_post_index = post_index
        elif line_type == "@":
            m = REGEX_PATCH_HEADER.search(line)
            if m is None:
                continue
            pre_index = int(m.groupdict()["pre_index"])
            post_index = int(m.groupdict()["post_index"])
            line_content = m.groupdict()["line_content"][:-1]

            if filemode == Filemode.NEW or filemode == Filemode.DELETE:
                pre_index = 1
                post_index = 1

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
        elif line_type == "\\":
            # This type of line shouldn't contain any secret; no need to set indices
            line_content = line[1:]

        if line_type and line_content is not None:
            yield Line(
                content=line_content,
                category=category,
                pre_index=line_pre_index,
                post_index=line_post_index,
            )


def get_padding(lines: List[Line]) -> int:
    """Return the number of digit of the maximum line number."""
    # value can be None
    return max(len(str(lines[-1].pre_index or 0)), len(str(lines[-1].post_index or 0)))


def get_offset(padding: int, is_patch: bool = False) -> int:
    """Return the offset due to the line prefix."""
    if is_patch:
        return len(PATCH_LINE_PREFIX.format("0" * padding, "0" * padding))

    return len(FILE_LINE_PREFIX.format("0" * padding))
