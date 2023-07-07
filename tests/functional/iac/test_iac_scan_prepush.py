from pathlib import Path
from subprocess import CalledProcessError

import pytest

from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.functional.utils import create_local_hook
from tests.repository import Repository


def test_iac_scan_prepush(tmp_path: Path) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    local_repo.create_commit()
    local_repo.push()

    # AND ggshield installed as a pre-push hook
    create_local_hook(tmp_path / "local" / ".git" / "hooks", "pre-push")

    # AND a vulnerability committed
    file = local_repo.path / "vuln.tf"
    file.write_text(_IAC_SINGLE_VULNERABILITY)
    local_repo.add("vuln.tf")
    local_repo.create_commit()

    # WHEN I try to push
    # THEN the hook prevents the push
    with pytest.raises(CalledProcessError) as exc:
        local_repo.push()

    # AND the error message contains the vulnerability
    stdout = exc.value.stdout.decode()
    assert "1 new incident" in stdout
    assert "vuln.tf" in stdout


def test_iac_scan_prepush_branch_without_new_commits(tmp_path: Path) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    # Add a commit to the remote repository, otherwise git complains the branch does not
    # contain anything
    local_repo.create_commit()
    local_repo.push()

    # AND ggshield installed as a pre-push hook
    create_local_hook(tmp_path / "local" / ".git" / "hooks", "pre-push")

    # AND a branch without new commits
    branch_name = "topic"
    local_repo.create_branch(branch_name)

    # WHEN I try to push the branch
    # THEN the hook does not crash
    local_repo.push("-u", "origin", branch_name)
