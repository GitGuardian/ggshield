from copy import deepcopy
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.utils import Filemode
from ggshield.scan import Commit, File, Result, Results
from ggshield.scan.repo import get_commits_by_batch, scan_commits_content
from ggshield.scan.scannable import CommitInformation
from tests.unit.conftest import TWO_POLICY_BREAKS


@pytest.mark.parametrize(
    "commits_sizes,batch_size,expected_batches",
    [
        (
            [1, 5, 6, 10, 2, 3, 1],
            20,
            [[1, 5, 6], [10, 2, 3, 1]],
        ),
        (
            [23, 2, 5, 6, 10, 2, 3, 1],
            20,
            [[23], [2, 5, 6], [10, 2, 3, 1]],
        ),
        (
            [1, 2, 5, 6, 10, 2, 3, 1, 23],
            20,
            [[1, 2, 5, 6], [10, 2, 3, 1], [23]],
        ),
        ([1], 20, [[1]]),
        (
            [1, 2, 5, 6, 10, 2, 3, 1, 23],
            100,
            [[1, 2, 5, 6, 10, 2, 3, 1, 23]],
        ),
        (
            [1, 2, 5, 6, 10, 2, 3, 1, 23],
            1,
            [[1], [2], [5], [6], [10], [2], [3], [1], [23]],
        ),
    ],
)
def test_get_commits_content_by_batch(
    commits_sizes: List[int],
    batch_size: int,
    expected_batches: List[List[int]],
):
    """
    GIVEN a set of commits containing a given number of files
    WHEN the number of files per commit varies
    THEN batches are still below the limit
    """
    commits = []
    for commit_nb, size in enumerate(commits_sizes):
        commit = Commit(sha=f"some_sha_{commit_nb}")
        commit.get_files = MagicMock(
            return_value=[
                File(
                    document=f"some content {file_nb}",
                    filename=f"some_filename_{file_nb}.py",
                )
                for file_nb in range(size)
            ]
        )
        commits.append(commit)
    batches = list(get_commits_by_batch(commits=commits, batch_max_size=batch_size))
    assert len(batches) == len(expected_batches)
    for (batch, expected_batch) in zip(batches, expected_batches):
        assert len(batch) == len(expected_batch)


@patch("ggshield.scan.repo.SecretScanner")
def test_scan_2_commits_same_content(secret_scanner_mock):
    """
    GIVEN 2 commits where each commit has a file with same content and same filename
    WHEN scan_commits_content returns 2 policy break for each commit
    THEN the total number of policy breaks is 4
    """
    commit_info = CommitInformation("unknown", "", "")
    commit_1 = Commit(sha="some_sha_1")
    commit_1._files = [File(document="document", filename="filename")]
    commit_1._info = commit_info

    commit_2 = Commit(sha="some_sha_2")
    commit_2._files = [File(document="document", filename="filename")]
    commit_2._info = commit_info

    secret_scanner_mock.return_value.scan.return_value = Results(
        results=[
            Result(
                filename="filename",
                content="document",
                filemode=Filemode.NEW,
                scan=deepcopy(TWO_POLICY_BREAKS),
            ),
            Result(
                filename="filename",
                content="document",
                filemode=Filemode.NEW,
                scan=deepcopy(TWO_POLICY_BREAKS),
            ),
        ],
        errors=[],
    )

    scan_collection = scan_commits_content(
        commits=[commit_1, commit_2],
        client=MagicMock(),
        cache=MagicMock(),
        matches_ignore=[],
        scan_context=MagicMock(),
        progress_callback=(lambda advance: None),
    )

    assert len(scan_collection.scans) == 2

    all_policy_breaks_count = sum(
        result.scan.policy_break_count for result in scan_collection.get_all_results()
    )
    assert all_policy_breaks_count == 4
