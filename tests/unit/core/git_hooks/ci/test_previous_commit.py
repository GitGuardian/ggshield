import os
from pathlib import Path
from typing import Callable
from unittest import mock

import pytest
from pytest import MonkeyPatch

from ggshield.core.git_hooks.ci.previous_commit import get_previous_commit_from_ci_env
from ggshield.utils.git_shell import EMPTY_SHA, git, is_valid_git_commit_ref
from ggshield.utils.os import cd
from tests.repository import Repository


def _setup_github_ci_env_new_branch(
    monkeypatch: MonkeyPatch,
    branch_name: str,
    head_sha: str,
    before_sha: str = EMPTY_SHA,
):
    monkeypatch.setenv("GITHUB_ACTIONS", "1")
    monkeypatch.setenv("GITHUB_PUSH_BEFORE_SHA", before_sha)
    monkeypatch.setenv("GITHUB_BASE_REF", "")
    monkeypatch.setenv("GITHUB_SHA", head_sha)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
    monkeypatch.setenv("GITHUB_REF_NAME", branch_name)


def _setup_gitlab_ci_env_new_branch(
    monkeypatch: MonkeyPatch,
    branch_name: str,
    head_sha: str,
    before_sha: str = EMPTY_SHA,
):
    monkeypatch.setenv("GITLAB_CI", "1")
    monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", before_sha)
    monkeypatch.setenv("CI_COMMIT_BRANCH", branch_name)
    monkeypatch.setenv("CI_COMMIT_SHA", head_sha)


def _setup_jenkins_ci_env_new_branch(
    monkeypatch: MonkeyPatch, branch_name: str, head_sha: str, before_sha: str = ""
):
    monkeypatch.setenv("JENKINS_HOME", "1")
    monkeypatch.setenv("GIT_PREVIOUS_COMMIT", before_sha)
    monkeypatch.setenv("GIT_BRANCH", branch_name)
    monkeypatch.setenv("GIT_COMMIT", head_sha)


def _setup_azure_ci_env_new_branch(
    monkeypatch: MonkeyPatch, branch_name: str, head_sha: str, before_sha: str = ""
):
    monkeypatch.setenv("BUILD_BUILDID", "1")
    monkeypatch.setenv("BUILD_SOURCEVERSION", before_sha)
    monkeypatch.setenv("BUILD_SOURCEBRANCHNAME", branch_name)


parametrized_ci_provider = pytest.mark.parametrize(
    "setup_ci_env",
    [
        _setup_github_ci_env_new_branch,
        _setup_gitlab_ci_env_new_branch,
        _setup_azure_ci_env_new_branch,
        _setup_jenkins_ci_env_new_branch,
    ],
    ids=["github", "gitlab", "azure_devops", "jenkins"],
)


@parametrized_ci_provider
@pytest.mark.parametrize("new_branch_commits_count", [0, 3])
def test_get_previous_commit_from_ci_env_new_branch(
    monkeypatch: MonkeyPatch,
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
    expected_sha = repository.create_commit()
    repository.push()

    # Setup new branch
    repository.create_branch("new-branch")
    head_sha = "HEAD"
    for _ in range(new_branch_commits_count):
        head_sha = repository.create_commit()

    with cd(repository.path), mock.patch.dict(os.environ, clear=True):
        # Simulate CI env
        setup_ci_env(monkeypatch, "new-branch", head_sha)
        found_sha = get_previous_commit_from_ci_env()

    assert found_sha is not None, "No previous commit SHA found"
    found_sha_evaluated = git(["rev-parse", found_sha], cwd=repository.path)
    assert found_sha_evaluated == expected_sha


@parametrized_ci_provider
def test_get_previous_commit_from_ci_env_new_repo(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    setup_ci_env: Callable[[MonkeyPatch, str, str], None],
):
    """
    GIVEN   a new, empty repository
    WHEN    calculating the commit sha previous to the first push,
            in a simulated CI env
    THEN    None is returned
    """
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    repository = Repository.clone(remote_repository.path, tmp_path / "local")

    repository.create_commit()

    with cd(repository.path), mock.patch.dict(os.environ, clear=True):
        # Simulate CI env
        setup_ci_env(monkeypatch, "new-branch", "HEAD")
        assert get_previous_commit_from_ci_env() is None


@parametrized_ci_provider
def test_get_previous_commit_from_ci_env_sub_branch_forced_push(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    setup_ci_env: Callable[[MonkeyPatch, str, str], None],
) -> None:
    """
    GIVEN   a repository with:
            - a commit pushed on the main branch
            - another branch created from main, with commits pushed
            - a local history rewritten
    WHEN    calculating the commit sha previous to the forced push,
            in a simulated CI env where new-branch is newly pushed
    THEN    the commit SHA (previous HEAD) returned does not exist anymore
            and a scan all is triggered instead
    """
    # Setup main branch
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    repository = Repository.clone(remote_repository.path, tmp_path / "local")
    repository.create_commit()
    repository.push()

    # Setup new branch
    branch_name = "new-branch"
    repository.create_branch(branch_name)
    before_sha = repository.create_commit()

    repository.git("commit", "--amend", "--allow-empty", "-m", "message")
    repository.remove_unreachable_commits()

    assert not is_valid_git_commit_ref(before_sha)
    assert before_sha != repository.get_top_sha()

    with cd(repository.path), mock.patch.dict(os.environ, clear=True):
        # Simulate CI env
        setup_ci_env(monkeypatch, branch_name, "HEAD", before_sha)
        found_sha = get_previous_commit_from_ci_env()

    assert found_sha is None


@parametrized_ci_provider
def test_get_previous_commit_from_ci_env_default_branch_forced_push(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    setup_ci_env: Callable[[MonkeyPatch, str, str], None],
):
    """
    GIVEN   a new, empty repository
    WHEN    calculating the commit sha previous to the first push,
            in a simulated CI env
    THEN    None is returned
    """
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    repository = Repository.clone(remote_repository.path, tmp_path / "local")

    repository.create_commit()
    before_sha = repository.create_commit()

    repository.git("commit", "--amend", "--allow-empty", "-m", "message")
    repository.remove_unreachable_commits()

    assert not is_valid_git_commit_ref(before_sha)
    assert before_sha != repository.get_top_sha()

    with cd(repository.path), mock.patch.dict(os.environ, clear=True):
        # Simulate CI env
        setup_ci_env(monkeypatch, "new-branch", "HEAD", before_sha)
        assert get_previous_commit_from_ci_env() is None


@parametrized_ci_provider
def test_get_previous_commit_from_ci_env_all_commits_forced_push(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    setup_ci_env: Callable[[MonkeyPatch, str, str], None],
):
    """
    GIVEN   a new, empty repository
    WHEN    calculating the commit sha previous to the first push,
            in a simulated CI env
    THEN    None is returned
    """
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    repository = Repository.clone(remote_repository.path, tmp_path / "local")

    before_sha = repository.create_commit()
    repository.git("commit", "--amend", "--allow-empty", "-m", "message")
    repository.remove_unreachable_commits()

    assert not is_valid_git_commit_ref(before_sha)
    assert before_sha != repository.get_top_sha()

    with cd(repository.path), mock.patch.dict(os.environ, clear=True):
        # Simulate CI env
        setup_ci_env(monkeypatch, "new-branch", "HEAD", before_sha)
        assert get_previous_commit_from_ci_env() is None
