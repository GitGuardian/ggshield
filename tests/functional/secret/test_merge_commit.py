from pathlib import Path
from subprocess import CalledProcessError

import pytest

from tests.functional.utils_create_merge_repo import (
    SecretLocation,
    generate_repo_with_merge_commit,
)


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

        # AND the error message contains the Gitlab Token
        captured = capsys.readouterr()
        assert "GitLab Token" in captured.err
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

    # AND the error message contains the Gitlab Token
    stderr = exc.value.stderr.decode()
    assert "GitLab Token" in stderr
