from typing import List

from ggshield.core.text_utils import LINE_DISPLAY, Line


def get_padding(lines: List[Line]) -> int:
    """Return the number of digit of the maximum line number."""
    # value can be None
    return max(len(str(lines[-1].pre_index or 0)), len(str(lines[-1].post_index or 0)))


def get_offset(padding: int, is_patch: bool = False) -> int:
    """Return the offset due to the line display."""
    if is_patch:
        return len(LINE_DISPLAY["patch"].format("0" * padding, "0" * padding))

    return len(LINE_DISPLAY["file"].format("0" * padding))
