from typing import Any, Dict, Optional, Union

import click

from .constants import IncidentStatus


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
    "secret_type": {"fg": "bright_yellow", "bold": True},
    "occurrence_count": {"fg": "bright_yellow", "bold": True},
    "ignore_sha": {"fg": "bright_yellow", "bold": True},
}


def format_text(text: str, style: Dict[str, Any]) -> str:
    """Return the formatted text with the given style."""
    return click.style(
        text, fg=style["fg"], bold=style.get("bold", False), dim=style.get("dim", False)
    )


def pluralize(name: str, nb: int, plural: Union[str, None] = None) -> str:
    # Note: 0 is plural in english
    if nb == 1:
        return name
    return plural or (name + "s")


def format_line_count(line_count: Union[int, None], padding: int) -> str:
    """Return the padded line count."""
    if line_count is None:
        return " " * padding

    return " " * max(0, padding - len(str(line_count))) + str(line_count)


def format_bool(value: bool) -> str:
    return "YES" if value else "NO"


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


def clip_long_line(
    content: str,
    max_length: int,
    before: bool = False,
    after: bool = False,
    min_length: int = 10,
    is_patch: bool = False,
) -> str:
    """
    Add a "…" character before and/or after the given string
    if it exceeds a maximum length.
    """
    ellipsis = "…"

    if is_patch:
        # If we are clipping a patch, move the first character out of `content` so that
        # we can keep it visible. It's important because this character is the patch
        # symbol.
        prefix = content[:1]
        content = content[1:]
        max_length -= 1
    else:
        prefix = ""

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
    return prefix + content


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
