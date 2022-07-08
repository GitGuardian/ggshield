from enum import Enum, auto
from typing import Any, Dict, NamedTuple, Optional, Union

import click


LINE_DISPLAY = {"file": "{} | ", "patch": "{} {} | "}

STYLE: Dict[str, Dict[str, Any]] = {
    "nb_secrets": {"fg": "bright_blue", "bold": True},
    "filename": {"fg": "bright_yellow", "bold": True},
    "commit_info": {"fg": "bright_yellow", "bold": False},
    "patch": {"fg": "white"},
    "key": {"fg": "bright_white", "bold": True},
    "secret": {"fg": "bright_red"},
    "error": {"fg": "red"},
    "no_secret": {"fg": "white"},
    "detector": {"fg": "bright_yellow", "bold": True},
    "policy": {"fg": "cyan", "bold": True},
    "ignore_sha": {"fg": "cyan"},
    "detector_line_start": {"fg": "cyan"},
    "line_count": {"fg": "white", "dim": True},
    "line_count_secret": {"fg": "yellow"},
    "progress": {"fg": "bright_yellow", "bold": False},
    "warning": {"fg": "yellow"},
}


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
            return LINE_DISPLAY["file"].format(
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

        return LINE_DISPLAY["patch"].format(
            format_text(pre_index, line_count_style),
            format_text(post_index, line_count_style),
        )


def format_text(text: str, style: Dict[str, Any]) -> str:
    """Return the formatted text with the given style."""
    return click.style(
        text, fg=style["fg"], bold=style.get("bold", False), dim=style.get("dim", False)
    )


def pluralize(name: str, nb: int, plural: Union[str, None] = None) -> str:
    if nb == 1:
        return name
    return plural or (name + "s")


def format_line_count(line_count: Union[int, None], padding: int) -> str:
    """Return the padded line count."""
    if line_count is None:
        return " " * padding

    return " " * max(0, padding - len(str(line_count))) + str(line_count)


def display_error(msg: str) -> None:
    click.echo(format_text(msg, STYLE["error"]), err=True)


def display_warning(msg: str) -> None:
    click.echo(format_text(msg, STYLE["warning"]), err=True)


def display_info(msg: str, nl: bool = True) -> None:
    click.echo(msg, nl=nl, err=True)


_VALIDITY_TEXT_FOR_ID = {
    "unknown": "Unknown",
    # cannot_check is the old ID for secrets for which there are no checkers
    "cannot_check": "Cannot Check",
    "no_checker": "No Checker",
    "failed_to_check": "Failed to Check",
    "not_checked": "Not Checked",
    "invalid": "Invalid",
    "valid": "Valid",
}


def translate_validity(validity_id: Optional[str]) -> str:
    if validity_id is None:
        validity_id = "unknown"
    # If we don't have a text for the validity_id, return it as is. We assume the text
    # of the ID is more valuable than a generic "Unknown" string
    return _VALIDITY_TEXT_FOR_ID.get(validity_id, validity_id)
