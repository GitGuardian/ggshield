from typing import List
from unittest.mock import MagicMock

import pytest

from ggshield.scan import Commit, File
from ggshield.scan.repo import get_commits_by_batch


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
