import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import List, Optional
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import ExitCode, ServiceUnavailableError, UnexpectedError
from ggshield.core.scan import Commit, ScanContext, ScanMode
from ggshield.core.scan.commit_information import CommitInformation
from ggshield.core.scan.commit_utils import CommitScannable
from ggshield.verticals.secret import Result, Results
from ggshield.verticals.secret.repo import (
    get_commits_by_batch,
    scan_commit_range,
    scan_commits_content,
)
from ggshield.verticals.secret.secret_scan_collection import SecretScanCollection
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


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_stops_on_error(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes
):
    """
    GIVEN a range of commits, scanned one commit per batch
    WHEN scanning one of them raises
    THEN the exception propagates
    AND the remaining batches are not scanned
    """
    nb_commits = 50
    started = []

    def scan(commits, *args):
        started.append(commits)
        if len(started) == 3:
            raise RuntimeError("boom")
        time.sleep(0.05)
        return SecretScanCollection(id="batch", type="commit-range", scans=[])

    scan_commits_content_mock.side_effect = scan
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: Commit(
        sha=sha,
        patch_parser=MagicMock(),
        info=CommitInformation(author="", email="", date="", paths=[Path("f")]),
    )
    client = MagicMock()
    client.secret_scan_preferences.maximum_documents_per_scan = 1

    with pytest.raises(RuntimeError, match="boom"):
        scan_commit_range(
            client=client,
            cache=MagicMock(),
            commit_list=[f"sha{i}" for i in range(nb_commits)],
            output_handler=MagicMock(),
            exclusion_regexes=set(),
            scan_context=ScanContext(scan_mode=ScanMode.PRE_RECEIVE, command_path="x"),
            secret_config=SecretConfig(),
        )

    assert len(started) < nb_commits


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_stops_sending_batches_after_a_failed_one(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes
):
    """
    GIVEN a range of commits, scanned one commit per batch
    WHEN the API does not scan one of them
    THEN the error is raised
    AND the remaining batches are not scanned
    """
    nb_commits = 50
    started = []

    def scan(commits, *args):
        started.append(commits)
        if commits[0].sha == "sha2":
            raise ServiceUnavailableError("throttled")
        time.sleep(0.05)
        return SecretScanCollection(id="batch", type="commit-range", scans=[])

    scan_commits_content_mock.side_effect = scan
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: Commit(
        sha=sha,
        patch_parser=MagicMock(),
        info=CommitInformation(author="", email="", date="", paths=[Path("f")]),
    )
    client = MagicMock()
    client.secret_scan_preferences.maximum_documents_per_scan = 1

    with pytest.raises(ServiceUnavailableError, match="throttled"):
        scan_commit_range(
            client=client,
            cache=MagicMock(),
            commit_list=[f"sha{i}" for i in range(nb_commits)],
            output_handler=MagicMock(),
            exclusion_regexes=set(),
            scan_context=ScanContext(scan_mode=ScanMode.PRE_RECEIVE, command_path="x"),
            secret_config=SecretConfig(),
        )

    assert len(started) < nb_commits


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_scans_batches_in_parallel(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes
):
    """
    GIVEN 2 batches and 2 workers
    WHEN scanning
    THEN the second batch starts before the first one ends
    """
    events = []

    def scan(commits, *args):
        events.append("start")
        time.sleep(0.1)
        events.append("end")
        return SecretScanCollection(id="batch", type="commit-range", scans=[])

    scan_commits_content_mock.side_effect = scan
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: Commit(
        sha=sha,
        patch_parser=MagicMock(),
        info=CommitInformation(author="", email="", date="", paths=[Path("f")]),
    )
    client = MagicMock()
    client.secret_scan_preferences.maximum_documents_per_scan = 1

    scan_commit_range(
        client=client,
        cache=MagicMock(),
        commit_list=["sha1", "sha2"],
        output_handler=MagicMock(),
        exclusion_regexes=set(),
        scan_context=ScanContext(scan_mode=ScanMode.PRE_RECEIVE, command_path="x"),
        secret_config=SecretConfig(),
    )

    # Sequential scanning would give ["start", "end", "start", "end"]
    assert events[:2] == ["start", "start"]


def _batch_with_secret(sha: str) -> SecretScanCollection:
    scannable = CommitScannable(sha, Path("f"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT)
    result = Result.from_scan_result(
        scannable, deepcopy(TWO_POLICY_BREAKS), secret_config=SecretConfig()
    )
    commit_scan = SecretScanCollection(
        id=sha, type="commit", results=Results(results=[result], errors=[])
    )
    return SecretScanCollection(id="batch", type="commit-range", scans=[commit_scan])


def _scan_commit_range_of_batches(
    scan_commits_content_mock,
    from_sha_mock,
    batches,
    started_together: Optional[threading.Barrier] = None,
):
    """
    Scan one commit per batch, scan_commits_content answering batch i with
    batches[i]: a SecretScanCollection, or an exception to raise. With
    `started_together`, no batch answers before they have all started.
    """

    def scan(commits, *args):
        if started_together is not None:
            started_together.wait(timeout=5)
        batch = batches[int(commits[0].sha)]
        if isinstance(batch, Exception):
            raise batch
        return batch

    scan_commits_content_mock.side_effect = scan
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: Commit(
        sha=sha,
        patch_parser=MagicMock(),
        info=CommitInformation(author="", email="", date="", paths=[Path("f")]),
    )
    client = MagicMock()
    client.secret_scan_preferences.maximum_documents_per_scan = 1
    output_handler = MagicMock()
    output_handler.process_scan.side_effect = lambda collection: (
        ExitCode.SCAN_FOUND_PROBLEMS
        if collection.total_secrets_count
        else ExitCode.SUCCESS
    )

    exit_code = scan_commit_range(
        client=client,
        cache=MagicMock(),
        commit_list=[str(i) for i in range(len(batches))],
        output_handler=output_handler,
        exclusion_regexes=set(),
        scan_context=ScanContext(scan_mode=ScanMode.PRE_RECEIVE, command_path="x"),
        secret_config=SecretConfig(),
    )
    return exit_code, output_handler.process_scan.call_args.args[0]


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 1)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_reports_secrets_found_before_a_failed_batch(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes
):
    """
    GIVEN a batch with a secret, then a batch the API did not scan
    WHEN scanning the commit range
    THEN the secret is reported and the command fails with exit code 1
    AND the failure is part of the report
    """
    exit_code, collection = _scan_commit_range_of_batches(
        scan_commits_content_mock,
        from_sha_mock,
        [_batch_with_secret("0"), ServiceUnavailableError("throttled")],
    )

    assert exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert collection.total_secrets_count > 0
    assert collection.results is not None
    assert [
        "throttled" in error.description for error in collection.results.errors
    ] == [True]


@pytest.mark.parametrize("forbidden_first", [True, False])
@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_failure_that_cannot_be_skipped_wins(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes, forbidden_first
):
    """
    GIVEN two batches running together, one failing with an error
    --no-fail-on-server-error cannot skip, one throttled
    WHEN scanning the commit range
    THEN the error the flag cannot skip is raised whatever the order
    """
    failures = [UnexpectedError("forbidden"), ServiceUnavailableError("throttled")]
    if not forbidden_first:
        failures.reverse()

    # A batch that has not started when another fails is cancelled, so both
    # batches must already be running for both failures to exist
    with pytest.raises(UnexpectedError, match="forbidden"):
        _scan_commit_range_of_batches(
            scan_commits_content_mock,
            from_sha_mock,
            failures,
            started_together=threading.Barrier(2),
        )


@pytest.mark.parametrize(
    "exception, expected",
    [
        pytest.param(
            ServiceUnavailableError("throttled"),
            ServiceUnavailableError,
            id="API did not scan",
        ),
        pytest.param(RuntimeError("parse bug"), UnexpectedError, id="other error"),
    ],
)
@patch("ggshield.verticals.secret.repo.SecretScanner")
def test_scan_commits_content_lets_scan_failures_through(
    secret_scanner_mock, exception, expected
):
    """
    GIVEN a scanner that raises
    WHEN scan_commits_content is called
    THEN the error propagates instead of being turned into an error message,
    so the command cannot exit 0
    """
    secret_scanner_mock.return_value.scan.side_effect = exception
    commit = Commit(
        sha="sha",
        patch_parser=lambda commit: [],
        info=CommitInformation(author="", email="", date="", paths=[]),
    )

    with pytest.raises(expected):
        scan_commits_content(
            commits=[commit],
            client=MagicMock(),
            cache=MagicMock(),
            scan_context=MagicMock(),
            progress_callback=(lambda advance: None),
            commit_scanned_callback=(lambda commit: None),
            secret_config=SecretConfig(),
        )
