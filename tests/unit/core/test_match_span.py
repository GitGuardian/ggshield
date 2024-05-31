from typing import List
from unittest.mock import Mock

import pytest
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.match_span import MatchSpan
from ggshield.core.scan import Commit, ScanContext, ScanMode, StringScannable
from ggshield.verticals.secret import SecretScanner
from tests.unit.conftest import (
    _MULTI_SECRET_ONE_LINE_FULL_PATCH,
    _PATCH_WITH_NONEWLINE_BEFORE_SECRET,
    _SECRET_RAW_FILE,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_MOVE_PATCH,
    my_vcr,
)


@pytest.mark.parametrize(
    ["name", "content", "is_patch", "expected_spans"],
    [
        pytest.param(
            "single_add",
            _SINGLE_ADD_PATCH,
            True,
            [MatchSpan(1, 1, 10, 79)],
            id="add",
        ),
        pytest.param(
            "single_move",
            _SINGLE_MOVE_PATCH,
            True,
            [MatchSpan(2, 2, 10, 79)],
            id="move",
        ),
        pytest.param(
            "single_delete",
            _SINGLE_DELETE_PATCH,
            True,
            [MatchSpan(2, 2, 10, 79)],
            id="delete",
        ),
        pytest.param(
            "single_file",
            _SECRET_RAW_FILE,
            False,
            [MatchSpan(0, 0, 11, 80)],
            id="file",
        ),
        pytest.param(
            "no_newline_before_secret",
            _PATCH_WITH_NONEWLINE_BEFORE_SECRET,
            True,
            [MatchSpan(5, 5, 10, 79)],
            id="no_newline_before_secret",
        ),
        pytest.param(
            "multiple_secret_one_line",
            _MULTI_SECRET_ONE_LINE_FULL_PATCH,
            True,
            [MatchSpan(1, 1, 16, 31), MatchSpan(1, 1, 53, 85)],
            id="multiple_secret_one_line",
        ),
    ],
)
def test_from_span(
    client: GGClient,
    cache: Cache,
    name: str,
    content: str,
    is_patch: bool,
    expected_spans: List[MatchSpan],
):
    if is_patch:
        commit = Commit.from_patch(content)
        files = commit.get_files()
    else:
        files = [StringScannable(content=content, url="test_file")]
    with my_vcr.use_cassette(name):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
        )
        results = scanner.scan(files, scanner_ui=Mock())
        result = results.results[0]

    matches = [
        match
        for policy_break in result.scan.policy_breaks
        for match in policy_break.matches
    ]
    for expected_span, match in zip(expected_spans, matches):
        assert match.span == expected_span

    assert len(expected_spans) == len(matches)
