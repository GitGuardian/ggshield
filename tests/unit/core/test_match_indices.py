from typing import List

import pytest
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.lines import get_lines_from_content
from ggshield.core.match_indices import MatchIndices, find_match_indices
from ggshield.core.scan import Commit, Files, ScanContext, ScanMode, StringScannable
from ggshield.verticals.secret import SecretScanner
from tests.unit.conftest import (
    _PATCH_WITH_NONEWLINE_BEFORE_SECRET,
    _SECRET_RAW_FILE,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_MOVE_PATCH,
    my_vcr,
)


@pytest.mark.parametrize(
    ["name", "content", "is_patch", "expected_indices_list"],
    [
        pytest.param(
            "single_add",
            _SINGLE_ADD_PATCH,
            True,
            [MatchIndices(1, 1, 10, 79)],
            id="add",
        ),
        pytest.param(
            "single_move",
            _SINGLE_MOVE_PATCH,
            True,
            [MatchIndices(2, 2, 10, 79)],
            id="move",
        ),
        pytest.param(
            "single_delete",
            _SINGLE_DELETE_PATCH,
            True,
            [MatchIndices(2, 2, 10, 79)],
            id="delete",
        ),
        pytest.param(
            "single_file",
            _SECRET_RAW_FILE,
            False,
            [MatchIndices(0, 0, 11, 80)],
            id="file",
        ),
        pytest.param(
            "no_newline_before_secret",
            _PATCH_WITH_NONEWLINE_BEFORE_SECRET,
            True,
            [MatchIndices(5, 5, 10, 79)],
            id="no_newline_before_secret",
        ),
    ],
)
def test_make_indices_patch(
    client: GGClient,
    cache: Cache,
    name: str,
    content: str,
    is_patch: bool,
    expected_indices_list: List[MatchIndices],
):
    if is_patch:
        o = Commit()
        o._patch = content
    else:
        o = Files([StringScannable(content=content, url="test_file")])
    with my_vcr.use_cassette(name):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
        )
        results = scanner.scan(o.files)
        result = results.results[0]

    lines = get_lines_from_content(
        content=result.content,
        filemode=result.filemode,
        is_patch=is_patch,
    )
    matches = [
        match
        for policy_break in result.scan.policy_breaks
        for match in policy_break.matches
    ]
    for expected_indices, match in zip(expected_indices_list, matches):
        match_indices = find_match_indices(match, lines, is_patch=is_patch)
        assert expected_indices.line_index_start == match_indices.line_index_start
        assert expected_indices.line_index_end == match_indices.line_index_end
        assert expected_indices.index_start == match_indices.index_start
        assert expected_indices.index_end == match_indices.index_end

    assert len(expected_indices_list) == len(matches)
