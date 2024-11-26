from typing import List

import pytest

from ggshield.core.lines import Line, get_lines_from_patch, get_offset, get_padding
from ggshield.utils.git_shell import Filemode


@pytest.mark.parametrize(
    "input, padding, want",
    [
        pytest.param(
            Line(content="", is_patch=False, pre_index=300),
            3,
            "\x1b[37m\x1b[22m\x1b[2m300\x1b[0m | ",
            id="file: padding==index",
        ),
        pytest.param(
            Line(content="", is_patch=False, pre_index=299),
            5,
            "\x1b[37m\x1b[22m\x1b[2m  299\x1b[0m | ",
            id="file: padding!=index",
        ),
        pytest.param(
            Line(content="", is_patch=True, post_index=297),
            3,
            "\x1b[37m\x1b[22m\x1b[2m   \x1b[0m \x1b[37m\x1b[22m\x1b[2m297\x1b[0m | ",
            id="addition",
        ),
        pytest.param(
            Line(content="", is_patch=True, pre_index=26),
            3,
            "\x1b[37m\x1b[22m\x1b[2m 26\x1b[0m \x1b[37m\x1b[22m\x1b[2m   \x1b[0m | ",
            id="deletion",
        ),
        pytest.param(
            Line(content="", is_patch=True, pre_index=294, post_index=29),
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


NO_NEWLINE_BEFORE_SECRET = """
@@ -1,3 +1,3 @@
 some line
 some other line
-deleted line
\\ No newline at end of file
+token = "foo"
\\ No newline at end of file
"""


def test_get_lines_from_patch_does_not_fail_on_patches_without_eof_newlines():
    """
    GIVEN a patch with the "No newline at end of file" indicator
    WHEN parsed with get_lines_from_patch()
    THEN it does not fail
    AND returns the correct lines
    """
    lines = list(get_lines_from_patch(NO_NEWLINE_BEFORE_SECRET, Filemode.MODIFY))
    assert [x.content for x in lines] == [
        "@@ -1,3 +1,3 @@",
        " some line",
        " some other line",
        "-deleted line",
        "\\ No newline at end of file",
        '+token = "foo"',
        "\\ No newline at end of file",
    ]


LINE_ON_HUNK_HEADER = """
@@ -3,4 +3,4 @@ I'm on the hunk header
 a line
 some other line

-old line
+new line
"""


def test_get_lines_set_indices_for_line_on_hunk_header():
    """
    GIVEN a patch with content on the same line as the patch header
    WHEN parsed with get_lines_from_patch()
    THEN the line at the patch header has valid values for pre_index and post_index
    """
    lines = list(get_lines_from_patch(LINE_ON_HUNK_HEADER, Filemode.MODIFY))
    assert lines[0].pre_index == 2
    assert lines[0].post_index == 2
