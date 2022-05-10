from typing import Optional

import pytest

from ggshield.core.text_utils import Line, LineCategory, translate_validity


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
