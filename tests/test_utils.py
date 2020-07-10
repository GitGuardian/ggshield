from typing import List

import pytest
from pygitguardian.models import Match

from ggshield.text_utils import Line, LineCategory
from ggshield.utils import update_policy_break_matches


@pytest.mark.parametrize(
    "matches,lines,is_patch,expected_matches",
    [
        pytest.param(
            [
                Match(
                    "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                    "GitHub Token",
                    index_start=22,
                    index_end=62,
                )
            ],
            [
                Line(pre_index=1, content="GutHub:", category=LineCategory.data),
                Line(
                    pre_index=2,
                    content="github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                    category=LineCategory.data,
                ),
                Line(pre_index=3, content="", category=LineCategory.data),
            ],
            False,
            [
                Match(
                    "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                    "GitHub Token",
                    line_start=1,
                    line_end=1,
                    index_start=14,
                    index_end=55,
                )
            ],
            id="files",
        ),
        pytest.param(
            [
                Match(
                    "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                    "GitHub Token",
                    index_start=40,
                    index_end=78,
                )
            ],
            [
                Line(
                    category=LineCategory.empty,
                    pre_index=None,
                    post_index=None,
                    content="@@ -0,0 +1,2 @",
                ),
                Line(
                    category=LineCategory.addition,
                    pre_index=None,
                    post_index=1,
                    content="GitHub:",
                ),
                Line(
                    category=LineCategory.addition,
                    pre_index=None,
                    post_index=2,
                    content="github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                ),
            ],
            False,
            [
                Match(
                    "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                    "GitHub Token",
                    line_start=2,
                    line_end=2,
                    index_start=17,
                    index_end=56,
                )
            ],
            id="patch",
        ),
    ],
)
def test_update_policy_break_matches(
    matches: List[Match],
    lines: List[Line],
    is_patch: bool,
    expected_matches: List[Match],
) -> None:
    update_policy_break_matches(matches, lines, is_patch=is_patch)

    for i, match in enumerate(expected_matches):
        assert match.index_start == matches[i].index_start
        assert match.line_start == matches[i].line_start
        assert match.index_end == matches[i].index_end
        assert match.line_end == matches[i].line_end
