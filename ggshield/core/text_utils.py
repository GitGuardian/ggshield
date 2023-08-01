import sys
from enum import Enum, auto
from typing import Any, Dict, List, NamedTuple, Optional, Union

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from .constants import IncidentStatus


LINE_DISPLAY = {"file": "{} | ", "patch": "{} {} | "}

LIGHT_GREY = (146, 146, 146)
ORANGE = (255, 128, 80)

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
    "detector_line_start": {"fg": "cyan"},
    "line_count": {"fg": "white", "dim": True},
    "line_count_secret": {"fg": "yellow"},
    "progress": {"fg": "bright_yellow", "bold": False},
    "warning": {"fg": "yellow"},
    "heading": {"fg": "green"},
    "incident_validity": {"fg": "bright_yellow", "bold": True},
    "policy_break_type": {"fg": "bright_yellow", "bold": True},
    "occurrence_count": {"fg": "bright_yellow", "bold": True},
    "ignore_sha": {"fg": "bright_yellow", "bold": True},
    "iac_vulnerability_critical": {"fg": "red", "bold": True},
    "iac_vulnerability_high": {"fg": ORANGE, "bold": True},
    "iac_vulnerability_medium": {"fg": "bright_yellow", "bold": True},
    "iac_vulnerability_low": {"fg": LIGHT_GREY, "bold": True},
    "iac_vulnerability_unknown": {"fg": "bright_yellow", "bold": True},
    "iac_deleted_vulnerability": {"fg": "green", "bold": True},
    "iac_remaining_vulnerability": {"fg": "yellow", "bold": True},
    "iac_new_vulnerability": {"fg": "bright_red", "bold": True},
    "iac_dim_summary": {"fg": LIGHT_GREY, "dim": True},
    # SCA related styles
    "sca_vulnerability_critical": {"fg": (255, 0, 0), "bold": True},  # red
    "sca_vulnerability_high": {"fg": (255, 128, 0), "bold": True},  # orange
    "sca_vulnerability_medium": {"fg": "bright_yellow", "bold": True},
    "sca_vulnerability_low": {"fg": (146, 146, 146), "bold": True},  # light-grey
    "sca_vulnerability_unknown": {"fg": "bright_yellow", "bold": True},
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


def display_heading(msg: str, nl: bool = True) -> None:
    click.echo(format_text(msg, STYLE["heading"]), nl=nl, err=True)


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


def create_progress_bar(doc_type: str) -> Progress:
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn(f"{{task.completed}} {doc_type} scanned out of {{task.total}}"),
        TimeRemainingColumn(),
        console=Console(file=sys.stderr),
    )


def get_padding(lines: List[Line]) -> int:
    """Return the number of digit of the maximum line number."""
    # value can be None
    return max(len(str(lines[-1].pre_index or 0)), len(str(lines[-1].post_index or 0)))


def get_offset(padding: int, is_patch: bool = False) -> int:
    """Return the offset due to the line display."""
    if is_patch:
        return len(LINE_DISPLAY["patch"].format("0" * padding, "0" * padding))

    return len(LINE_DISPLAY["file"].format("0" * padding))


def clip_long_line(
    content: str,
    max_length: int,
    before: bool = False,
    after: bool = False,
    min_length: int = 10,
) -> str:
    """
    Add a "…" character before and/or after the given string
    if it exceeds a maximum length.
    """
    ellipsis = "…"
    content_length = len(content)
    if content_length > max_length:
        if before and after and content_length > max_length + 1:
            content = (
                ellipsis
                + content[
                    (content_length - max(max_length, min_length)) // 2
                    + 1 : (content_length + max(max_length, min_length)) // 2
                    - 1
                ]
                + ellipsis
            )
        elif after:
            content = content[: max(max_length - 1, min_length)] + ellipsis
        elif before:
            content = ellipsis + content[min(-max_length + 1, -min_length) :]
    return content


def file_info(
    filename: str,
    incident_count: int,
    incident_status: IncidentStatus = IncidentStatus.DETECTED,
) -> str:
    """Return the formatted file info (number of incidents + filename)."""
    return "\n{} {}: {} {} {}\n".format(
        format_text(">", STYLE["detector_line_start"]),
        format_text(filename, STYLE["filename"]),
        incident_count,
        pluralize("incident", incident_count, "incidents"),
        incident_status.value,
    )


def file_diff_info(
    filename: str,
    new_incident_count: int,
    persisting_incident_count: Optional[int],
    deleted_incident_count: Optional[int],
) -> str:
    """Return the formatted file info (number of incidents + filename)."""
    incidents_count = [
        f"{new_incident_count} new {pluralize('incident', new_incident_count, 'incidents')} detected",
    ]
    if deleted_incident_count or persisting_incident_count:
        incidents_count.extend(
            [
                f"{deleted_incident_count} deleted",
                f"{persisting_incident_count} remaining",
            ]
        )
    return "\n{} {}: {}\n".format(
        format_text(">", STYLE["detector_line_start"]),
        format_text(filename, STYLE["filename"]),
        ", ".join(incidents_count),
    )
