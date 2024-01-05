from pathlib import Path
from typing import Callable

import pytest
from pytest import MonkeyPatch

from ggshield.core.git_hooks.ci.previous_commit import get_previous_commit_from_ci_env
from ggshield.utils.git_shell import EMPTY_SHA, git
from ggshield.utils.os import cd
from tests.repository import Repository


def _setup_github_ci_env_new_branch(
    monkeypatch: MonkeyPatch, branch_name: str, head_sha: str
):
    monkeypatch.setenv("GITHUB_ACTIONS", "1")
    monkeypatch.setenv("GITHUB_PUSH_BEFORE_SHA", EMPTY_SHA)
    monkeypatch.setenv("GITHUB_BASE_REF", "")
    monkeypatch.setenv("GITHUB_SHA", head_sha)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
    monkeypatch.setenv("GITHUB_REF_NAME", branch_name)


def _setup_gitlab_ci_env_new_branch(
    monkeypatch: MonkeyPatch, branch_name: str, head_sha: str
):
    monkeypatch.setenv("GITLAB_CI", "1")
    monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", EMPTY_SHA)
    monkeypatch.setenv("CI_COMMIT_BRANCH", branch_name)
    monkeypatch.setenv("CI_COMMIT_SHA", head_sha)


def _setup_jenkins_ci_env_new_branch(
    monkeypatch: MonkeyPatch, branch_name: str, head_sha: str
):
    monkeypatch.setenv("JENKINS_HOME", "1")
    monkeypatch.setenv("GIT_PREVIOUS_COMMIT", "")
    monkeypatch.setenv("GIT_BRANCH", branch_name)
    monkeypatch.setenv("GIT_COMMIT", head_sha)


def _setup_azure_ci_env_new_branch(
    monkeypatch: MonkeyPatch, branch_name: str, head_sha: str
):
    monkeypatch.setenv("BUILD_BUILDID", "1")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "")
    monkeypatch.setenv("BUILD_SOURCEBRANCHNAME", branch_name)


@pytest.mark.parametrize(
    "setup_ci_env",
    [
        _setup_github_ci_env_new_branch,
        _setup_gitlab_ci_env_new_branch,
        _setup_azure_ci_env_new_branch,
        _setup_jenkins_ci_env_new_branch,
    ],
    ids=["github", "gitlab", "azure_devops", "jenkins"],
)
@pytest.mark.parametrize("new_branch_commits_count", [0, 3])
def test_get_previous_commit_from_ci_env_new_branch(
    monkeypatch: MonkeyPatch,
    iac_single_vuln: str,
    tmp_path: Path,
    setup_ci_env: Callable[[MonkeyPatch, str, str], None],
    new_branch_commits_count: int,
) -> None:
    """
    GIVEN   a repository with:
            - a commit pushed on the main branch
            - a new branch created from main, with or without commits
    WHEN    calculating the commit sha previous to the push,
            in a simulated CI env where new-branch is newly pushed
    THEN    the last commit sha of the parent branch is returned
    """
    # Setup main branch
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    repository = Repository.clone(remote_repository.path, tmp_path / "local")
    ignored_file = repository.path / "ignored_file.tf"
    ignored_file.write_text(iac_single_vuln)
    repository.add(ignored_file)
    expected_sha = repository.create_commit()
    repository.push()

    # Setup new branch
    repository.create_branch("new-branch")
    head_sha = "HEAD"
    for i in range(new_branch_commits_count):
        scanned_file = repository.path / f"scanned_file{i}.tf"
        scanned_file.write_text(iac_single_vuln)
        repository.add(scanned_file)
        head_sha = repository.create_commit()

    # Simulate CI env
    setup_ci_env(monkeypatch, "new-branch", head_sha)

    with cd(repository.path):
        found_sha = get_previous_commit_from_ci_env(False)
    found_sha_evaluated = git(["rev-parse", found_sha], cwd=repository.path)
    assert found_sha_evaluated == expected_sha
