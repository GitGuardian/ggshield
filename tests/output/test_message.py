from typing import List

import pytest

from ggshield.core.text_utils import Line
from ggshield.output.text.message import (
    clip_long_line,
    format_line_count_break,
    no_leak_message,
)
from ggshield.output.text.utils import get_offset, get_padding


def test_message_no_secret(snapshot):
    msg = no_leak_message()
    snapshot.assert_match(msg)


@pytest.mark.parametrize(
    "lines, want",
    [
        pytest.param(
            [Line(content="", pre_index=4000, post_index=30)], 4, id="padding-pre_index"
        ),
        pytest.param(
            [Line(content="", pre_index=40, post_index=300)], 3, id="padding-post_index"
        ),
        pytest.param(
            [Line(content="", pre_index=4000)], 4, id="padding-pre_index-none"
        ),
        pytest.param(
            [Line(content="", post_index=300)], 3, id="padding-none-post_index"
        ),
    ],
)
def test_get_padding(lines: List[Line], want: int) -> None:
    assert get_padding(lines) == want


@pytest.mark.parametrize(
    "padding, is_patch, want",
    [pytest.param(4, True, 12, id="patch"), pytest.param(4, False, 7, id="file")],
)
def test_get_offset(padding: int, is_patch: bool, want: int) -> None:
    assert get_offset(padding, is_patch) == want


@pytest.mark.parametrize(
    "params, want",
    [
        # should not clip anything
        (("123456789", 10, False, False, 0), "123456789"),
        (("123456789", 10, True, False, 0), "123456789"),
        (("123456789", 10, False, True, 0), "123456789"),
        (("123456789", 10, True, True, 0), "123456789"),
        # edge case: should not clip anything
        (("123456789", 9, True, True, 0), "123456789"),
        # edge case: should only clip after
        (("123456789", 8, True, True, 0), "1234567…"),
        # should clip as expected
        (("123456789", 5, False, False, 0), "123456789"),
        (("123456789", 5, True, False, 0), "…6789"),
        (("123456789", 5, False, True, 0), "1234…"),
        (("123456789", 5, True, True, 0), "…456…"),
        (("123456789", 4, True, False, 0), "…789"),
        (("123456789", 4, False, True, 0), "123…"),
        (("123456789", 4, True, True, 0), "…45…"),
        (("123456789", 4, True, True, 6), "…3456…"),
    ],
)
def test_clip_long_line(params, want):
    assert clip_long_line(*params) == want


def test_format_line_count_break():
    assert format_line_count_break(5) == "\x1b[36m\x1b[22m\x1b[22m  ...\n\x1b[0m"
