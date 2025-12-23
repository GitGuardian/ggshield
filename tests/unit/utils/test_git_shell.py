import os
import platform
import subprocess
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Optional
from unittest.mock import Mock, patch

import pytest

from ggshield.core.tar_utils import tar_from_ref_and_filepaths
from ggshield.utils.git_shell import (
    GitExecutableNotFound,
    InvalidGitRefError,
    NotAGitDirectory,
    check_git_dir,
    check_git_ref,
    get_default_branch,
    get_filepaths_from_ref,
    get_new_branch_ci_commits,
    get_remotes,
    get_repository_url_from_path,
    get_staged_filepaths,
    git,
    git_ls_unstaged,
    is_git_available,
    is_git_dir,
    is_valid_git_commit_ref,
    simplify_git_url,
)
from ggshield.utils.os import cd
from tests.repository import Repository


def _add_remote(
    repository: Repository, repository_name: str, remote_name: Optional[str] = "origin"
):
    remote_url = f"https://github.com/owner/{repository_name}.git"
    repository.git("remote", "add", remote_name, remote_url)


def _create_repository_with_remote(
    repository_path: Path,
    repository_name: str,
    remote_name: Optional[str] = "origin",
):
    local_repo = Repository.create(repository_path, bare=True)
    _add_remote(local_repo, repository_name, remote_name)
    return local_repo


@patch("ggshield.utils.git_shell._get_git_path")
def test_is_git_available(_get_git_path_mock):
    _get_git_path_mock.side_effect = GitExecutableNotFound()
    assert not is_git_available()


def test_git_shell():
    assert "usage: git" in git(["help"])


def test_is_git_dir(tmp_path):
    assert is_git_dir(os.getcwd())
    assert not is_git_dir(str(tmp_path))


def test_is_valid_git_commit_ref():
    assert is_valid_git_commit_ref("HEAD")
    assert not is_valid_git_commit_ref("invalid_ref")


def test_get_new_branch_ci_commits(tmp_path: Path):
    # GIVEN a remote repository
    remote_repository = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone, with commitM pushed on main
    local_repository = Repository.clone(remote_repository.path, tmp_path / "local")
    local_repository.create_commit()
    local_repository.push()

    # AND commitA1 on new branchA
    local_repository.create_branch("branchA")
    commitA1_sha = local_repository.create_commit("commitA1")
    # AND commitB1 & B2 on new branchB, created from branchA
    local_repository.create_branch("branchB")
    commitB1_sha = local_repository.create_commit("commitB1")
    commitB2_sha = local_repository.create_commit("commitB2")
    # AND commitA2 created later on branchA
    local_repository.checkout("branchA")
    commitA2_sha = local_repository.create_commit("commitA2")

    # WHEN executing get_branch_new_commits
    # THEN only new commits are found for each branch
    local_repository.checkout("branchA")
    assert get_new_branch_ci_commits("branchA", local_repository.path) == [
        commitA2_sha,
        commitA1_sha,
    ]
    local_repository.checkout("branchB")
    assert get_new_branch_ci_commits("branchB", local_repository.path) == (
        [commitB2_sha, commitB1_sha, commitA1_sha]
    )


def test_get_branch_new_commits_many_branches(tmp_path: Path):
    # GIVEN a repository with many branches
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    local_repository = Repository.clone(remote_repository.path, tmp_path / "local")
    for i in range(50):
        local_repository.create_branch(f"branch_with_a_long_name{i}")
        local_repository.create_commit()
    local_repository.push("--all")

    # AND a local branch with one new commit
    local_repository.create_branch("tested-branch")
    tested_commit = local_repository.create_commit()
    # WHEN executing get_branch_new_commits
    # THEN it works as intended
    assert get_new_branch_ci_commits("tested-branch", local_repository.path) == [
        tested_commit
    ]


def test_check_git_dir(tmp_path):
    """
    GIVEN a git checkout
    AND check_git_dir() has been called without arguments in it
    AND it did not raise an exception
    WHEN the current directory is changed to a directory which is not a git checkout
    AND check_git_dir() is called without arguments
    THEN it raises an exception

    (this tests the LRU cache on the functions in git_shell.py works correctly)
    """
    check_git_dir()

    with cd(str(tmp_path)):
        with pytest.raises(NotAGitDirectory):
            check_git_dir()


def test_check_git_ref_invalid_git_path(tmp_path):
    # WHEN checking a non git path
    with cd(str(tmp_path)):
        # THEN function throws an error
        with pytest.raises(NotAGitDirectory):
            check_git_ref(ref="HEAD")


def test_check_git_ref_valid_git_path(tmp_path):
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo_path = tmp_path / "local"
    local_repo = Repository.clone(remote_repo.path, local_repo_path)
    local_repo.create_commit()
    local_repo.push()

    # THEN valid git references do not throw
    check_git_ref("HEAD", local_repo_path)
    check_git_ref("@{upstream}", local_repo_path)

    # AND other strings throw
    with pytest.raises(InvalidGitRefError):
        check_git_ref("invalid_ref", local_repo_path)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://user:password@github.com:84/GitGuardian/ggshield.git",
            "github.com/GitGuardian/ggshield",
        ),
        (
            "https://github.com/GitGuardian/ggshield.git",
            "github.com/GitGuardian/ggshield",
        ),
        (
            "git@github.com:GitGuardian/ggshield.git",
            "github.com/GitGuardian/ggshield",
        ),
        (
            "https://github.com/Git.Guar-di_an/gg.sh-ie_ld.git",
            "github.com/Git.Guar-di_an/gg.sh-ie_ld",
        ),
        (
            "https://gitlab.instance.ovh/owner/project/repository.git",
            "gitlab.instance.ovh/owner/project/repository",
        ),
        (
            "https://username@dev.azure.com/username/project/_git/repository",
            "dev.azure.com/username/project/repository",
        ),
        (
            "https://username@bitbucket.org/owner/repository.git",
            "bitbucket.org/owner/repository",
        ),
    ],
    ids=[
        "Full Github https",
        "Github https",
        "Github ssh",
        "Github special characters",
        "Gitlab https",
        "Azure Devops https",
        "BitBucket https",
    ],
)
def test_simplify_git_url(url, expected):
    assert expected == simplify_git_url(url)


def test_get_repository_url_from_path(tmp_path: Path):
    # GIVEN a local repository with remote url
    local_repo = _create_repository_with_remote(tmp_path, "repository")

    # THEN the remote url is returned in the root clone directory
    assert "repository" in get_repository_url_from_path(local_repo.path)
    # AND in a subdirectory
    subdirectory_path = local_repo.path / "subdirectory"
    subdirectory_path.mkdir()
    assert "repository" in get_repository_url_from_path(subdirectory_path)


def test_get_repository_url_from_path_no_repo(tmp_path: Path):
    # GIVEN a local directory with no remote git directory
    local_directory_path = tmp_path / "local"
    local_directory_path.mkdir()
    # AND a local repository with no remote git directory
    local_repository_path = tmp_path / "repo"
    repo = Repository.create(local_repository_path)
    repo.create_commit()

    # THEN no url is returned
    assert get_repository_url_from_path(local_directory_path) is None
    assert get_repository_url_from_path(local_repository_path) is None


def test_get_repository_url_from_path_two_remotes(tmp_path: Path):
    # GIVEN a local repository with two remotes
    local_repo = _create_repository_with_remote(
        repository_path=tmp_path,
        repository_name="repository1",
        remote_name="other_remote",
    )
    _add_remote(
        repository=local_repo,
        repository_name="repository2",
        remote_name="origin",
    )

    # THEN only one remote is returned, with priority to origin
    assert "repository2" in get_repository_url_from_path(local_repo.path)
    # AND in a subdirectory
    subdirectory_path = local_repo.path / "subdirectory"
    subdirectory_path.mkdir()
    assert "repository2" in get_repository_url_from_path(subdirectory_path)


def test_get_repository_url_from_path_different_repo(tmp_path: Path):
    # GIVEN two repositories with one remote each
    local_repo1 = _create_repository_with_remote(
        repository_path=tmp_path / "local1",
        repository_name="repository1",
    )
    local_repo2 = _create_repository_with_remote(
        repository_path=tmp_path / "local2",
        repository_name="repository2",
    )

    # THEN scanning repo 2 from repo 1 yields repo 2's remote url
    with cd(str(local_repo1.path)):
        assert "repository2" in get_repository_url_from_path(local_repo2.path)


def test_get_repository_url_from_path_subrepo(tmp_path: Path):
    # GIVEN two repositories, each with its remote, with repo2 nested inside repo1
    local_repo1 = _create_repository_with_remote(
        repository_path=tmp_path,
        repository_name="repository1",
    )
    local_repo2 = _create_repository_with_remote(
        repository_path=local_repo1.path / "nested",
        repository_name="repository2",
    )

    # THEN scanning local repo 1 returns remote repo 1 url
    assert "repository1" in get_repository_url_from_path(local_repo1.path)
    # AND scanning local repo 2 returns remote repo 2 url
    assert "repository2" in get_repository_url_from_path(local_repo2.path)


@pytest.mark.parametrize(
    ("has_remote", "env_var_value", "expected_result"),
    [
        # Repository with remote - remote takes precedence
        (True, None, "github.com/owner/repository"),
        (True, "https://github.com/fallback/repo.git", "github.com/owner/repository"),
        (True, "", "github.com/owner/repository"),
        # Repository without remote - fallback to env var
        (
            False,
            "https://github.com/fallback/repository.git",
            "github.com/fallback/repository",
        ),
        (False, None, None),
        (False, "", None),
    ],
    ids=[
        "repo_with_remote_no_env_var",
        "repo_with_remote_with_env_var_remote_wins",
        "repo_with_remote_empty_env_var",
        "repo_without_remote_with_env_var",
        "repo_without_remote_no_env_var",
        "repo_without_remote_empty_env_var",
    ],
)
def test_get_repository_url_from_path_with_fallback(
    tmp_path: Path,
    has_remote: bool,
    env_var_value: Optional[str],
    expected_result: Optional[str],
):
    """
    Test repository URL detection with GITGUARDIAN_GIT_REMOTE_FALLBACK_URL environment variable.
    Covers all combinations of having/not having a remote and having/not having env var.
    """
    # GIVEN a repository
    if has_remote:
        local_repo = _create_repository_with_remote(tmp_path, "repository")
        repo_path = local_repo.path
    else:
        local_repository_path = tmp_path / "repo"
        repo = Repository.create(local_repository_path)
        repo.create_commit()
        repo_path = local_repository_path

    # WHEN getting the repository URL with or without env var
    env_dict = (
        {"GITGUARDIAN_GIT_REMOTE_FALLBACK_URL": env_var_value}
        if env_var_value is not None
        else {}
    )
    with patch.dict(os.environ, env_dict, clear=False):
        url = get_repository_url_from_path(repo_path)

    # THEN the expected URL is returned
    assert url == expected_result


@pytest.mark.parametrize(
    ("env_var_value", "expected_result"),
    [
        # Non-git directory - fallback to env var
        (
            "https://github.com/fallback/repository.git",
            "github.com/fallback/repository",
        ),
        (None, None),
        ("", None),
    ],
    ids=[
        "non_git_dir_with_env_var",
        "non_git_dir_no_env_var",
        "non_git_dir_empty_env_var",
    ],
)
def test_get_repository_url_from_path_non_git_dir_with_fallback(
    tmp_path: Path,
    env_var_value: Optional[str],
    expected_result: Optional[str],
):
    """
    Test repository URL detection in non-git directories with GITGUARDIAN_GIT_REMOTE_FALLBACK_URL.
    """
    # GIVEN a local directory with no git repository
    local_directory_path = tmp_path / "local"
    local_directory_path.mkdir()

    # WHEN getting the repository URL with or without env var
    env_dict = (
        {"GITGUARDIAN_GIT_REMOTE_FALLBACK_URL": env_var_value}
        if env_var_value is not None
        else {}
    )
    with patch.dict(os.environ, env_dict, clear=False):
        url = get_repository_url_from_path(local_directory_path)

    # THEN the expected URL is returned
    assert url == expected_result


@pytest.mark.parametrize(
    ("fallback_url", "expected_simplified"),
    [
        (
            "https://github.com/owner/repo.git",
            "github.com/owner/repo",
        ),
        (
            "https://user:password@github.com:84/owner/repo.git",
            "github.com/owner/repo",
        ),
        (
            "git@gitlab.com:owner/repo.git",
            "gitlab.com/owner/repo",
        ),
        (
            "https://dev.azure.com/owner/project/_git/repository",
            "dev.azure.com/owner/project/repository",
        ),
    ],
    ids=[
        "simple_https_url",
        "https_with_credentials_and_port",
        "ssh_url",
        "azure_devops_url",
    ],
)
def test_get_repository_url_from_path_env_var_simplifies_url(
    tmp_path: Path,
    fallback_url: str,
    expected_simplified: str,
):
    """
    Test that GITGUARDIAN_GIT_REMOTE_FALLBACK_URL URLs are properly simplified.
    """
    # GIVEN a repository without a remote
    local_repository_path = tmp_path / "repo"
    repo = Repository.create(local_repository_path)
    repo.create_commit()

    # WHEN getting the repository URL with a complex fallback URL
    with patch.dict(os.environ, {"GITGUARDIAN_GIT_REMOTE_FALLBACK_URL": fallback_url}):
        url = get_repository_url_from_path(local_repository_path)

    # THEN the URL is simplified
    assert url == expected_simplified


@pytest.mark.parametrize(
    ("exception_type", "env_var_value", "expected_result"),
    [
        # Git command fails with CalledProcessError - fallback to env var
        (
            subprocess.CalledProcessError,
            "https://github.com/fallback/repository.git",
            "github.com/fallback/repository",
        ),
        (subprocess.CalledProcessError, None, None),
        # Git command fails with OSError - fallback to env var
        (
            OSError,
            "https://github.com/fallback/repository.git",
            "github.com/fallback/repository",
        ),
        (OSError, None, None),
    ],
    ids=[
        "called_process_error_with_env_var",
        "called_process_error_no_env_var",
        "os_error_with_env_var",
        "os_error_no_env_var",
    ],
)
def test_get_repository_url_from_path_with_git_command_error(
    tmp_path: Path,
    exception_type: type,
    env_var_value: Optional[str],
    expected_result: Optional[str],
):
    """
    Test that GITGUARDIAN_GIT_REMOTE_FALLBACK_URL is used when git command fails with an exception.
    This covers the exception handling block in get_repository_url_from_path.
    """
    # GIVEN a repository with a remote
    local_repo = _create_repository_with_remote(tmp_path, "repository")

    # AND the git command will raise an exception
    with patch("ggshield.utils.git_shell.git") as git_mock:
        if exception_type == subprocess.CalledProcessError:
            git_mock.side_effect = subprocess.CalledProcessError(
                1, ["git", "remote", "-v"], stderr=b"error"
            )
        else:  # OSError
            git_mock.side_effect = OSError("Permission denied")

        # WHEN getting the repository URL with or without env var
        env_dict = (
            {"GITGUARDIAN_GIT_REMOTE_FALLBACK_URL": env_var_value}
            if env_var_value is not None
            else {}
        )
        with patch.dict(os.environ, env_dict, clear=False):
            url = get_repository_url_from_path(local_repo.path)

    # THEN the fallback URL is returned (or None if no env var)
    assert url == expected_result


def test_get_filepaths_from_ref(tmp_path):
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a first commit
    first_file = repo.path / "first.py"
    first_content = "First file (included)"
    first_file.write_text(first_content)
    repo.add("first.py")
    repo.create_commit()

    # AND a second commit
    second_file = repo.path / "second.py"
    second_content = "Second file (not included)"
    second_file.write_text(second_content)
    repo.add("second.py")
    repo.create_commit()

    # WHEN scanning since the second commit
    filepaths = [str(path) for path in get_filepaths_from_ref("HEAD~1", tmp_path)]

    # THEN file from first commit is part of filepaths
    assert "first.py" in filepaths
    # AND file from second commit is not part of filepaths
    assert "second.py" not in filepaths


def test_get_staged_filepaths(tmp_path):
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a first commit
    first_file = repo.path / "first.py"
    first_content = "First file (included)"
    first_file.write_text(first_content)
    repo.add("first.py")
    repo.create_commit()

    # AND staged content
    second_file = repo.path / "second.py"
    second_content = "Second file (included)"
    second_file.write_text(second_content)
    repo.add("second.py")

    # WHEN scanning for files, including staged
    filepaths = [str(path) for path in get_staged_filepaths(tmp_path)]

    # THEN file from first commit is part of filepaths
    assert "first.py" in filepaths
    # AND staged file is part of filepaths
    assert "second.py" in filepaths


def test_tar_from_ref_and_filepaths(tmp_path):
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    first_file_name = "first.py"
    first_ignored_file_name = "first_ignored.py"
    second_file_name = "second.py"

    # AND a first commit
    first_file = repo.path / first_file_name
    first_content = "First file (included)"
    first_file.write_text(first_content)
    repo.add(first_file_name)

    first_ignored_file = repo.path / first_ignored_file_name
    first_ignored_content = "First file (filtered out)"
    first_ignored_file.write_text(first_ignored_content)
    repo.add(first_ignored_file_name)
    repo.create_commit()

    # AND a second commit
    second_file = repo.path / second_file_name
    second_content = "Second file (not included)"
    second_file.write_text(second_content)
    repo.add(second_file_name)
    repo.create_commit()

    # AND a list of filepaths
    filepaths = [first_file_name]

    # WHEN creating a tar
    tarbytes = tar_from_ref_and_filepaths(
        "HEAD~1", [Path(path_str) for path_str in filepaths], wd=tmp_path
    )

    tar_stream = BytesIO(tarbytes)
    with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
        filenames = tar.getnames()
        # THEN only first file in in tar
        assert filenames == [first_file_name]


def test_get_remotes(tmp_path):
    # GIVEN a repository with two remotes
    repo = Repository.create(tmp_path)
    repo.git("remote", "add", "origin", "https://a_remote_repo")
    repo.git("remote", "add", "upstream", "https://another_remote_repo")

    # wHEN listing remotes
    remotes = get_remotes(repo.path)

    # THEN all the remotes are listed
    assert set(remotes) == {"origin", "upstream"}


def test_get_default_branch_with_remote(tmp_path):
    # GIVEN a repository with a remote
    remote_repository = Repository.create(tmp_path / "remote", initial_branch="foo")
    remote_repository.create_commit()
    local_repository = Repository.clone(remote_repository.path, tmp_path / "local")

    # WHEN getting the default branch
    default_branch = get_default_branch(local_repository.path)

    # THEN the default branch is the remote initial branch
    assert default_branch == "origin/foo"


def test_get_default_branch_without_remote(tmp_path):
    # GIVEN a repository without a remote
    local_repository = Repository.create(tmp_path / "remote", initial_branch="foo")
    local_repository.git("config", "--local", "init.defaultBranch", "foo")

    # WHEN getting the default branch
    default_branch = get_default_branch(local_repository.path)

    # THEN the default branch is the initial branch
    assert default_branch == "foo"


def test_git_ls_unstaged(tmp_path):
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a submodule
    submodule = Repository.create(repo.path / "submodule")
    submodule.create_commit()

    repo.git("submodule", "add", submodule.path)

    # AND unstaged files
    repo_file = repo.path / "repo_file"
    submodule_file = repo.path / "submodule" / "submodule_file"
    repo_file.write_text("Content")
    submodule_file.write_text("Content")

    # WHEN listing unstaged files
    unstaged_files = git_ls_unstaged(wd=repo.path)

    # THEN unstaged files in repo and submodule are returned
    # as relative to repo.path
    expected_paths = {x.relative_to(repo.path) for x in (repo_file, submodule_file)}
    assert {Path(x) for x in unstaged_files} == expected_paths


@patch("subprocess.run", return_value=Mock(stdout=b""))
def test_git_command_includes_longpaths_on_windows(mock_run):
    # GIVEN any git command
    git(["status"])
    mock_run.assert_called_once()

    # THEN the command includes core.longpaths=true if on Windows
    command = mock_run.call_args[0][0]
    longpaths_included = any(param == "core.longpaths=true" for param in command)
    if platform.system() == "Windows":
        assert (
            longpaths_included
        ), f"core.longpaths=true not found in command: {command}"
    else:
        assert (
            not longpaths_included
        ), f"core.longpaths=true found in command: {command}"
