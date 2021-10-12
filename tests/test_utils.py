import pytest

from ggshield.scan import Commit
from ggshield.scan.scannable import File, Files
from ggshield.utils import (
    MatchIndices,
    SupportedScanMode,
    find_match_indices,
    get_lines_from_content,
)
from tests.conftest import (
    _SECRET_RAW_FILE,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_MOVE_PATCH,
    my_vcr,
)


@pytest.mark.parametrize(
    ["name", "content", "is_patch", "expected_indices_l"],
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
    ],
)
def test_make_indices_patch(client, cache, name, content, is_patch, expected_indices_l):
    if is_patch:
        o = Commit()
        o._patch = content
    else:
        o = Files([File(content, "test_file")])
    with my_vcr.use_cassette(name):
        results = o.scan(
            client=client,
            cache=cache,
            matches_ignore={},
            all_policies=True,
            verbose=False,
            mode_header=SupportedScanMode.PATH.value,
            banlisted_detectors=None,
        )
        result = results[0]

    lines = get_lines_from_content(
        content=result.content,
        filemode=result.filemode,
        is_patch=is_patch,
        show_secrets=True,
    )
    matches = [
        match
        for policy_break in result.scan.policy_breaks
        for match in policy_break.matches
    ]
    for i, match in enumerate(matches):
        expected_indices = expected_indices_l[i]
        match_indices = find_match_indices(match, lines, is_patch=is_patch)
        assert expected_indices.line_index_start == match_indices.line_index_start
        assert expected_indices.line_index_end == match_indices.line_index_end
        assert expected_indices.index_start == match_indices.index_start
        assert expected_indices.index_end == match_indices.index_end
