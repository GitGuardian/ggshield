import re
from enum import Enum, auto
from types import SimpleNamespace
from typing import Iterable, List, Optional

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
    ADDITION = auto()
    DATA = auto()
    DELETION = auto()
    EMPTY = auto()


class Line(SimpleNamespace):
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
    is_part_of_patch: bool = False

    def __hash__(self):
        return hash(
            (
                self.content,
                self.category,
                self.pre_index,
                self.post_index,
                self.is_part_of_patch,
            )
        )

    def build_line_count(self, padding: int, is_secret: bool = False) -> str:
        """Return the formatted line count."""
        line_count_style = (
            STYLE["line_count_secret"] if is_secret else STYLE["line_count"]
        )
        if self.category is not None and not isinstance(self.category, LineCategory):
            raise TypeError("line category invalid")

        # File
        if self.category == LineCategory.DATA:
            return FILE_LINE_PREFIX.format(
                format_text(
                    format_line_count(self.pre_index, padding), line_count_style
                )
            )

        # Patch
        pre_index = format_line_count(self.pre_index, padding)
        post_index = format_line_count(self.post_index, padding)

        if self.category == LineCategory.ADDITION:
            pre_index = " " * padding

        elif self.category == LineCategory.DELETION:
            post_index = " " * padding

        return PATCH_LINE_PREFIX.format(
            format_text(pre_index, line_count_style),
            format_text(post_index, line_count_style),
        )

    @property
    def number(self) -> int:
        index = self.pre_index or self.post_index
        if index:
            index += int(self.is_part_of_patch)
        else:
            index = -1
        return index


def get_lines_from_content(content: str, filemode: Filemode) -> List[Line]:
    """
    Return the secrets and the lines with line number.

    :param content: Content to scan
    :param filemode: Filemode of the content
    """

    # Patch
    if filemode != Filemode.FILE:
        return list(get_lines_from_patch(content, filemode))

    # File
    return list(get_lines_from_file(content))


def get_lines_from_file(content: str) -> Iterable[Line]:
    """Return the lines with line number from a file."""
    for line_count, line_content in enumerate(content.split("\n")):
        yield Line(
            content=line_content, category=LineCategory.DATA, pre_index=line_count + 1
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
                category = LineCategory.EMPTY
        elif line_type == "+":
            post_index += 1
            line_post_index = post_index
            line_content = line[1:]
            category = LineCategory.ADDITION
        elif line_type == "-":
            pre_index += 1
            line_pre_index = pre_index
            line_content = line[1:]
            category = LineCategory.DELETION
        elif line_type == "\\":
            # This type of line shouldn't contain any secret; no need to set indices
            line_content = line[1:]

        if line_type and line_content is not None:
            yield Line(
                content=line_content,
                category=category,
                pre_index=line_pre_index,
                post_index=line_post_index,
                is_part_of_patch=True,
            )


def get_padding(lines: List[Line]) -> int:
    """Return the number of digit of the maximum line number."""
    return max(len(str(lines[-1].pre_index or 0)), len(str(lines[-1].post_index or 0)))


def get_offset(padding: int, is_patch: bool = False) -> int:
    """Return the offset due to the line prefix."""
    if is_patch:
        return len(PATCH_LINE_PREFIX.format("0" * padding, "0" * padding))

    return len(FILE_LINE_PREFIX.format("0" * padding))
