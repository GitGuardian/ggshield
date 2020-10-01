from typing import List

import pytest

from ggshield.output.text.message import format_line_count_break, no_leak_message
from ggshield.output.text.text_output import get_offset, get_padding
from ggshield.text_utils import Line


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


def test_format_line_count_break():
    assert format_line_count_break(5) == "\x1b[36m\x1b[22m\x1b[22m  ...\n\x1b[0m"
