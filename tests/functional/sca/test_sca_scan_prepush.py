import re
from pathlib import Path
from subprocess import CalledProcessError
from typing import List, Optional

import pytest

from tests.functional.utils import create_local_hook
from tests.repository import Repository


def test_sca_scan_prepush(tmp_path: Path, pipfile_lock_with_vuln) -> None:
    """
    GIVEN a remote repository and a local clone
    GIVEN ggshield installed as a pre-push hook
    WHEN I try to push
    THEN the hook prevents the push
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    local_repo.create_commit()
    local_repo.push()

    create_local_hook(tmp_path / "local" / ".git" / "hooks", "sca", "pre-push")

    dep_file = local_repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    local_repo.add("Pipfile.lock")
    local_repo.create_commit()

    with pytest.raises(CalledProcessError) as exc:
        local_repo.push()

    stdout = exc.value.stdout.decode()
    assert bool(re.search(r"> Pipfile\.lock: \d+ incidents? detected", stdout))


def test_sca_scan_prepush_branch_without_new_commits(tmp_path: Path) -> None:
    """
    GIVEN a remote repository and a local clone
    GIVEN ggshield installed as a pre-push hook
    GIVEN a branch without new commits
    WHEN I try to push the branch
    THEN the hook does not crash
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    # Add a commit to the remote repository, otherwise git complains the branch does not
    # contain anything
    local_repo.create_commit()
    local_repo.push()

    branch_name = "topic"
    local_repo.create_branch(branch_name)

    create_local_hook(tmp_path / "local" / ".git" / "hooks", "sca", "pre-push")

    local_repo.push("-u", "origin", branch_name)


@pytest.mark.parametrize("scan_args", [None, ["--all"]])
def test_sca_scan_prepush_vuln_before_hook(
    tmp_path: Path, scan_args: Optional[List[str]], pipfile_lock_with_vuln
) -> None:
    """
    GIVEN a remote repository and a local clone with a vulnerability
    GIVEN ggshield later installed as a pre-push hook
    GIVEN changes that does not introduce new vulnerabilities
    WHEN I TRY TO PUSH
    THEN the hook prevents the push if and only if --all is specified
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    dep_file = local_repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    local_repo.add("Pipfile.lock")
    local_repo.create_commit()
    local_repo.push()

    create_local_hook(
        tmp_path / "local" / ".git" / "hooks", "sca", "pre-push", args=scan_args
    )

    file = local_repo.path / "non_sca.txt"
    file.write_text("This should not be detected")
    local_repo.add("non_sca.txt")
    local_repo.create_commit()

    if scan_args is None:
        local_repo.push()
    else:
        with pytest.raises(CalledProcessError) as exc:
            local_repo.push()
            stdout = exc.value.stdout.decode()
            assert "vuln_before_hook.tf" in stdout
