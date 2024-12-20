from copy import deepcopy
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import Commit
from ggshield.core.scan.commit_information import CommitInformation
from ggshield.core.scan.commit_utils import CommitScannable
from ggshield.verticals.secret import Result, Results
from ggshield.verticals.secret.repo import get_commits_by_batch, scan_commits_content
from tests.unit.conftest import _ONE_LINE_AND_MULTILINE_PATCH_CONTENT, TWO_POLICY_BREAKS


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
    AND commit patches are not fully parsed (we want to delay parsing them until the
    last moment)
    """
    never_called_parser = MagicMock()

    commits = [
        Commit(
            sha=f"some_sha_{idx}",
            patch_parser=never_called_parser,
            info=CommitInformation(
                author="",
                email="",
                date="",
                paths=[Path(f"file{file_idx}") for file_idx in range(size)],
            ),
        )
        for idx, size in enumerate(commits_sizes)
    ]

    batches = list(get_commits_by_batch(commits=commits, batch_max_size=batch_size))

    never_called_parser.assert_not_called()

    for batch, expected_batch in zip(batches, expected_batches):
        assert len(batch) == len(expected_batch)
    assert len(batches) == len(expected_batches)


@patch("ggshield.verticals.secret.repo.SecretScanner")
def test_scan_2_commits_same_content(secret_scanner_mock):
    """
    GIVEN 2 commits where each commit has a file with same content and same filename
    WHEN scan_commits_content returns 2 policy break for each commit
    THEN the total number of policy breaks is 4
    """
    path = Path("filename")
    content = _ONE_LINE_AND_MULTILINE_PATCH_CONTENT
    commit_1_files = [CommitScannable("some_sha_1", path, content)]
    commit_1 = Commit(
        sha="some_sha_1",
        patch_parser=lambda commit: commit_1_files,
        info=(
            CommitInformation(
                author="",
                email="",
                date="",
                paths=[path],
            )
        ),
    )

    commit_2_files = [CommitScannable("some_sha_2", path, content)]
    commit_2 = Commit(
        sha="some_sha_2",
        patch_parser=lambda commit: commit_2_files,
        info=(
            CommitInformation(
                author="",
                email="",
                date="",
                paths=[path],
            )
        ),
    )

    secret_scanner_mock.return_value.scan.return_value = Results(
        results=[
            Result.from_scan_result(
                commit_1_files[0],
                scan_result=deepcopy(TWO_POLICY_BREAKS),
                secret_config=SecretConfig(),
            ),
            Result.from_scan_result(
                commit_2_files[0],
                scan_result=deepcopy(TWO_POLICY_BREAKS),
                secret_config=SecretConfig(),
            ),
        ],
        errors=[],
    )

    scan_collection = scan_commits_content(
        commits=[commit_1, commit_2],
        client=MagicMock(),
        cache=MagicMock(),
        scan_context=MagicMock(),
        progress_callback=(lambda advance: None),
        commit_scanned_callback=(lambda commit: None),
        secret_config=SecretConfig(),
    )

    assert len(scan_collection.scans) == 2

    all_secrets_count = sum(
        len(result.secrets) for result in scan_collection.get_all_results()
    )
    assert all_secrets_count == 4


@patch("ggshield.verticals.secret.repo.SecretScanner")
def test_scan_2_commits_file_association(secret_scanner_mock):
    """
    GIVEN 2 commits with several files in some commits
    WHEN scan_commits_content returns results with policy breaks for some of the files
    THEN the files and policy breaks are associated with the correct commits
    """
    sha1 = "some_sha_1"
    file1_1 = CommitScannable(
        sha1, Path("filename1"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document1"
    )
    file1_2 = CommitScannable(
        sha1, Path("filename2"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document2"
    )
    file1_3 = CommitScannable(
        sha1, Path("filename3"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document3"
    )
    file1_list = [file1_1, file1_2, file1_3]

    commit_1 = Commit(
        sha=sha1,
        patch_parser=lambda commit: file1_list,
        info=CommitInformation(
            author="",
            email="",
            date="",
            paths=[x.path for x in file1_list],
        ),
    )

    sha2 = "some_sha_2"
    file2_1 = CommitScannable(
        sha2, Path("filename2"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document2"
    )
    file2_2 = CommitScannable(
        sha2, Path("filename3"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document3"
    )
    file2_list = [file2_1, file2_2]

    commit_2 = Commit(
        sha=sha2,
        patch_parser=lambda commit: file2_list,
        info=CommitInformation(
            author="",
            email="",
            date="",
            paths=[x.path for x in file2_list],
        ),
    )

    policy_breaks_file_1_1 = deepcopy(TWO_POLICY_BREAKS)
    policy_breaks_file_1_3 = deepcopy(TWO_POLICY_BREAKS)
    policy_breaks_file_2_1 = deepcopy(TWO_POLICY_BREAKS)
    secret_scanner_mock.return_value.scan.return_value = Results(
        results=[
            Result.from_scan_result(
                file1_3,
                scan_result=policy_breaks_file_1_3,
                secret_config=SecretConfig(),
            ),
            Result.from_scan_result(
                file2_1,
                scan_result=policy_breaks_file_2_1,
                secret_config=SecretConfig(),
            ),
            Result.from_scan_result(
                file1_1,
                scan_result=policy_breaks_file_1_1,
                secret_config=SecretConfig(),
            ),
        ],
        errors=[],
    )

    scan_collection = scan_commits_content(
        commits=[commit_1, commit_2],
        client=MagicMock(),
        cache=MagicMock(),
        scan_context=MagicMock(),
        progress_callback=(lambda advance: None),
        commit_scanned_callback=(lambda commit: None),
        secret_config=SecretConfig(),
    )

    assert len(scan_collection.scans) == 2

    # out of 3 files, only 2 results were returned
    assert sorted(
        scan_collection.scans[0].results.results, key=lambda f: f.filename
    ) == sorted(
        [
            Result.from_scan_result(
                file1_3, policy_breaks_file_1_3, secret_config=SecretConfig()
            ),
            Result.from_scan_result(
                file1_1, policy_breaks_file_1_1, secret_config=SecretConfig()
            ),
        ],
        key=lambda f: f.filename,
    )

    # out of 2 files, only 1 result was returned
    assert scan_collection.scans[1].results.results == [
        Result.from_scan_result(
            file2_1, policy_breaks_file_2_1, secret_config=SecretConfig()
        ),
    ]
