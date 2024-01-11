from subprocess import CalledProcessError

import pytest

from tests.conftest import IAC_NO_VULNERABILITIES, IAC_SINGLE_VULNERABILITY


def test_iac_scan_prereceive(iac_repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a vulnerable file to my local repo
    vuln_file_name = "file1.tf"
    vuln_path = iac_repo_with_hook.path / vuln_file_name

    vuln_path.write_text(IAC_SINGLE_VULNERABILITY)

    iac_repo_with_hook.add(str(vuln_path))
    iac_repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook prevents the push
    with pytest.raises(CalledProcessError) as exc:
        iac_repo_with_hook.push()

    # AND the error message contains the vulnerability details
    stderr = exc.value.stderr.decode()
    assert "1 new incident" in stderr
    assert vuln_file_name in stderr


def test_iac_scan_prereceive_no_vuln(iac_repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a non vulnerable IaC file to my local repo
    non_vuln_file_name = "file_no_vuln.tf"
    non_vuln_path = iac_repo_with_hook.path / non_vuln_file_name

    non_vuln_path.write_text(IAC_NO_VULNERABILITIES)

    iac_repo_with_hook.add(str(non_vuln_path))
    iac_repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook accepts the push
    iac_repo_with_hook.push()


def test_iac_scan_prereceive_no_iac(iac_repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a non IaC file to my local repo
    non_iac_file_name = "file1.txt"
    non_iac_path = iac_repo_with_hook.path / non_iac_file_name

    non_iac_path.write_text("Not an IaC file.")

    iac_repo_with_hook.add(str(non_iac_path))
    iac_repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook accepts the push
    iac_repo_with_hook.push()


def test_iac_scan_prereceive_all(iac_repo_with_hook_all) -> None:
    # GIVEN a repo and remote with pre-receive hook set with the --all option
    # WHEN I add a vulnerable file to my local repo
    vuln_file_name = "file1.tf"
    vuln_path = iac_repo_with_hook_all.path / vuln_file_name

    vuln_path.write_text(IAC_SINGLE_VULNERABILITY)

    iac_repo_with_hook_all.add(str(vuln_path))
    iac_repo_with_hook_all.create_commit()

    # WHEN I try to push
    # THEN the hook, set to scan all, prevents the push
    with pytest.raises(CalledProcessError) as exc:
        iac_repo_with_hook_all.push()

    # AND the error message contains the leaked secret
    stderr = exc.value.stderr.decode()
    # testing the all variant of the output
    assert "1 incident detected" in stderr
    assert vuln_file_name in stderr


def test_iac_scan_prereceive_branch_without_new_commits(iac_repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I push a new branch with a single empty commit
    branch_name = "topic"
    iac_repo_with_hook.create_branch(branch_name)
    iac_repo_with_hook.create_commit()

    # WHEN I try to push the branch
    # THEN the hook does not crash
    iac_repo_with_hook.push("-u", "origin", branch_name)
