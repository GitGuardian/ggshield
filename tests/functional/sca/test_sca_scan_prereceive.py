import re
from subprocess import CalledProcessError

import pytest


def test_sca_scan_prereceive(sca_repo_with_hook, pipfile_lock_with_vuln) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a vulnerable file to my local repo

    dep_file = sca_repo_with_hook.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    sca_repo_with_hook.add("Pipfile.lock")
    sca_repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook prevents the push
    with pytest.raises(CalledProcessError) as exc:
        sca_repo_with_hook.push()

    # AND the error message contains the vulnerability details
    stderr = exc.value.stderr.decode()
    assert bool(re.search(r"> Pipfile\.lock: \d+ incidents? detected", stderr))


def test_sca_scan_prereceive_no_vuln(sca_repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a non vulnerable SCA file to my local repo
    dep_file = sca_repo_with_hook.path / "Pipfile.lock"
    dep_file.write_text("")

    sca_repo_with_hook.add("Pipfile.lock")
    sca_repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook accepts the push
    sca_repo_with_hook.push()


def test_sca_scan_prereceive_no_sca(sca_repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a non SCA file to my local repo
    non_sca_file_name = "file1.txt"
    non_sca_path = sca_repo_with_hook.path / non_sca_file_name

    non_sca_path.write_text("Not an SCA file.")

    sca_repo_with_hook.add(str(non_sca_path))
    sca_repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook accepts the push
    sca_repo_with_hook.push()


def test_sca_scan_prereceive_all(
    sca_repo_with_hook_all, pipfile_lock_with_vuln
) -> None:
    # GIVEN a repo and remote with pre-receive hook set with the --all option
    # WHEN I add a vulnerable file to my local repo
    dep_file = sca_repo_with_hook_all.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    sca_repo_with_hook_all.add("Pipfile.lock")
    sca_repo_with_hook_all.create_commit()

    # WHEN I try to push
    # THEN the hook, set to scan all, prevents the push
    with pytest.raises(CalledProcessError) as exc:
        sca_repo_with_hook_all.push()

    # AND the error message contains the leaked secret
    stderr = exc.value.stderr.decode()
    # testing the all variant of the output
    assert bool(re.search(r"> Pipfile\.lock: \d+ incidents? detected", stderr))


def test_sca_scan_prereceive_branch_without_new_commits(sca_repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I push a new branch with a single empty commit
    branch_name = "topic"
    sca_repo_with_hook.create_branch(branch_name)
    sca_repo_with_hook.create_commit()

    # WHEN I try to push the branch
    # THEN the hook does not crash
    sca_repo_with_hook.push("-u", "origin", branch_name)
