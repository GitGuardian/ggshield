from pathlib import Path
from subprocess import CalledProcessError

import pytest

from tests.functional.utils_create_merge_repo import (
    SecretLocation,
    generate_repo_with_merge_commit,
)

pytestmark = pytest.mark.uses_gitguardian_api


EXPECTED_CONFLICT_DETECTORS = {
    "GitLab Token",
    "Generic High Entropy Secret",
}


def assert_conflict_secret_detected(stderr: str) -> None:
    assert "1 secret detected" in stderr
    assert "glpat-" in stderr
    assert any(detector in stderr for detector in EXPECTED_CONFLICT_DETECTORS)


@pytest.mark.parametrize(
    "with_conflict",
    [
        True,
        False,
    ],
)
@pytest.mark.parametrize(
    "secret_location",
    [
        SecretLocation.MASTER_BRANCH,
        SecretLocation.FEATURE_BRANCH,
        SecretLocation.NO_SECRET,
    ],
)
@pytest.mark.parametrize(
    "scan_all_merge_files",
    [
        True,
        False,
    ],
)
def test_merge_commit_no_conflict(
    capsys,
    tmp_path: Path,
    with_conflict: bool,
    secret_location: SecretLocation,
    scan_all_merge_files: bool,
) -> None:

    if (
        secret_location == SecretLocation.MASTER_BRANCH
        and with_conflict
        and scan_all_merge_files
    ):
        with pytest.raises(CalledProcessError):
            generate_repo_with_merge_commit(
                tmp_path,
                with_conflict=with_conflict,
                secret_location=secret_location,
                scan_all_merge_files=scan_all_merge_files,
            )

        # AND the error message contains the expected secret
        captured = capsys.readouterr()
        assert_conflict_secret_detected(captured.err)
    else:
        generate_repo_with_merge_commit(
            tmp_path,
            with_conflict=with_conflict,
            secret_location=secret_location,
            scan_all_merge_files=scan_all_merge_files,
        )


def test_merge_commit_with_conflict_and_secret_in_conflict(
    tmp_path: Path,
) -> None:

    with pytest.raises(CalledProcessError) as exc:
        generate_repo_with_merge_commit(
            tmp_path, with_conflict=True, secret_location=SecretLocation.CONFLICT_FILE
        )

    # AND the error message contains the expected secret
    stderr = exc.value.stderr.decode()
    assert_conflict_secret_detected(stderr)
