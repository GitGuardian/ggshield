from typing import List, Optional

import pytest

from ggshield.core.text_utils import (
    Line,
    LineCategory,
    clip_long_line,
    get_offset,
    get_padding,
    translate_validity,
)


def test_line_validation():
    line_to_test = Line("hello", category=" ")  # type: ignore
    with pytest.raises(TypeError):
        line_to_test.build_line_count(0, False)
    Line("hello", category=None).build_line_count(0)


@pytest.mark.parametrize(
    "input, padding, want",
    [
        pytest.param(
            Line(content="", category=LineCategory.data, pre_index=300),
            3,
            "\x1b[37m\x1b[22m\x1b[2m300\x1b[0m | ",
            id="file: padding==index",
        ),
        pytest.param(
            Line(content="", category=LineCategory.data, pre_index=299),
            5,
            "\x1b[37m\x1b[22m\x1b[2m  299\x1b[0m | ",
            id="file: padding!=index",
        ),
        pytest.param(
            Line(content="", category=LineCategory.addition, post_index=297),
            3,
            "\x1b[37m\x1b[22m\x1b[2m   \x1b[0m \x1b[37m\x1b[22m\x1b[2m297\x1b[0m | ",
            id="addition",
        ),
        pytest.param(
            Line(content="", category=LineCategory.deletion, pre_index=26),
            3,
            "\x1b[37m\x1b[22m\x1b[2m 26\x1b[0m \x1b[37m\x1b[22m\x1b[2m   \x1b[0m | ",
            id="deletion",
        ),
        pytest.param(
            Line(content="", category=LineCategory.empty, pre_index=294, post_index=29),
            3,
            "\x1b[37m\x1b[22m\x1b[2m294\x1b[0m \x1b[37m\x1b[22m\x1b[2m 29\x1b[0m | ",
            id="addition",
        ),
    ],
)
def test_build_line_count(input: Line, padding: int, want: str) -> None:
    result = input.build_line_count(padding)
    assert result == want


@pytest.mark.parametrize(
    "validity_id, expected",
    [
        ("unknown", "Unknown"),
        (None, "Unknown"),
        ("valid", "Valid"),
        ("unexpected_status", "unexpected_status"),
    ],
)
def test_translate_validity(validity_id: Optional[str], expected: str):
    result = translate_validity(validity_id)
    assert result == expected


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
