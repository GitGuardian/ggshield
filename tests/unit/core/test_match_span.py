from typing import List

import pytest
from pygitguardian.models import ScanResult

from ggshield.core.lines import get_lines_from_content
from ggshield.core.match_span import MatchSpan
from ggshield.utils.git_shell import Filemode
from tests.unit.conftest import (
    _MULTI_SECRET_ONE_LINE_PATCH,
    _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    _MULTI_SECRET_TWO_LINES_PATCH,
    _MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_MULTILINE_PATCH,
    _SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_PATCH,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
)


@pytest.mark.parametrize(
    ["content", "scan_result", "expected_spans"],
    [
        pytest.param(
            _SIMPLE_SECRET_PATCH,
            _SIMPLE_SECRET_PATCH_SCAN_RESULT,
            [MatchSpan(1, 1, 15, 56)],
            id="1match",
        ),
        pytest.param(
            _MULTI_SECRET_ONE_LINE_PATCH,
            _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
            [
                MatchSpan(1, 1, 17, 32),
                MatchSpan(1, 1, 54, 86),
            ],
            id="multimatch-1line",
        ),
        pytest.param(
            _MULTI_SECRET_TWO_LINES_PATCH,
            _MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
            [
                MatchSpan(1, 1, 17, 32),
                MatchSpan(2, 2, 21, 53),
            ],
            id="multimatch-2lines",
        ),
        pytest.param(
            _SIMPLE_SECRET_MULTILINE_PATCH,
            _SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
            [
                MatchSpan(2, 10, 9, 32),
            ],
            id="1match-multiline",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            [
                MatchSpan(1, 1, 18, 33),
                MatchSpan(1, 1, 36, 68),
                MatchSpan(1, 9, 69, 30),
                MatchSpan(9, 9, 38, 107),
            ],
            id="1line-1multiline",
        ),
    ],
)
def test_from_match(
    content: str,
    scan_result: ScanResult,
    expected_spans: List[MatchSpan],
):
    """
    GIVEN a patch content
    AND its scan result
    WHEN MatchSpan.from_match() is called on all the result matches
    THEN the created MatchSpans are equal to the expected spans
    """
    lines = get_lines_from_content(content, filemode=Filemode.NEW)

    matches = [
        match
        for policy_break in scan_result.policy_breaks
        for match in policy_break.matches
    ]
    for idx, (expected_span, match) in enumerate(zip(expected_spans, matches)):
        span = MatchSpan.from_match(match, lines)
        assert span == expected_span, f"Error on match[{idx}]"

    assert len(expected_spans) == len(matches)
