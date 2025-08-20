import logging
import os
import platform
import re
import subprocess
from enum import Enum
from functools import lru_cache
from pathlib import Path
from shutil import which
from typing import List, Optional, Union

from ggshield.utils.os import getenv_int


EMPTY_SHA = "0000000000000000000000000000000000000000"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

COMMAND_TIMEOUT = getenv_int("GG_GIT_TIMEOUT", 45)

logger = logging.getLogger(__name__)


class GitError(Exception):
    pass


class InvalidGitRefError(GitError):
    """
    Raised when the git reference does not exist
    """

    def __init__(self, ref: str):
        super().__init__(f"Not a git reference: {ref}.")


class NotAGitDirectory(GitError):
    def __init__(self):
        super().__init__("Not a git directory.")


class GitExecutableNotFound(GitError):
    pass


class GitCommandTimeoutExpired(GitError):
    pass


class Filemode(Enum):
    """
    Enum class for git filemode.
    """

    MODIFY = "modified file"
    DELETE = "deleted file"
    NEW = "new file"
    RENAME = "renamed file"
    FILE = "file"
    UNKNOWN = "unknown"


def is_git_available() -> bool:
    try:
        _get_git_path()
        return True
    except GitExecutableNotFound:
        return False


@lru_cache(None)
def _get_git_path() -> str:
    git_path = which("git")

    if git_path is None:
        raise GitExecutableNotFound("unable to find git executable in PATH/PATHEXT")

    # lower()ing these would provide additional coverage on case-
    # insensitive filesystems but detection is problematic
    git_path = os.path.abspath(git_path)
    cwd = os.getcwd()
    path_env = [
        os.path.abspath(p) for p in os.environ.get("PATH", "").split(os.pathsep)
    ]

    # git was found - ignore git in cwd if cwd not in PATH
    if cwd == os.path.dirname(git_path) and cwd not in path_env:
        raise GitExecutableNotFound("rejecting git executable in CWD not in PATH")

    logger.debug("Found git at %s", git_path)
    return git_path


@lru_cache(None)
def _git_rev_parse_absolute(option: str, wd_absolute: Path) -> Optional[str]:
    """
    Helper function for `_git_rev_parse` to only cache on absolute paths.
    """
    try:
        return git(["rev-parse", option], cwd=wd_absolute, log_stderr=False)
    except subprocess.CalledProcessError:
        return None


def _git_rev_parse(option: str, wd: Path) -> Optional[str]:
    return _git_rev_parse_absolute(option=option, wd_absolute=wd.resolve())


def get_new_branch_ci_commits(
    branch: str, wd: Path, remote: str = "origin"
) -> List[str]:
    """
    Returns a list of commits that only exist on the given branch.
    This is intended to be used for new branches only, in a CI env.
    """
    # https://stackoverflow.com/q/14848274
    refs_format = f"refs/remotes/{remote}/"
    all_branches = git(
        [
            "for-each-ref",
            "--format=%(refname)",
            refs_format,
        ],
        cwd=wd,
    ).splitlines()
    other_branches = (b for b in all_branches if b != f"{refs_format}{branch}")

    return git(
        ["log", "HEAD", "--not", *other_branches, "--format=format:%H"], cwd=wd
    ).splitlines()


def simplify_git_url(url: str) -> str:
    """
    Removes elements from the git remote url.
    - scheme
    - credentials
    - port
    - extension
    https://user:pass@mygitlab.corp.com:84/path/to/repo.git -> mygitlab.corp.com/toto/titi/tata
    """
    for pattern, replace in (
        (r"https?://", ""),  # Scheme
        (r".+@", ""),  # Credentials
        (r":\d*/", "/"),  # Port
        (r"\.git$", ""),  # Github/Gitlab/BitBucket extension (**.git)
        (r"/_git/", "/"),  # Azure Devops extension (**/_git/**)
        (":", "/"),  # Normalize ssh url to https format
    ):
        url = re.sub(pattern, replace, url)
    return url


def is_git_dir(wd: Union[str, Path]) -> bool:
    return _git_rev_parse("--git-dir", Path(wd)) is not None


def is_git_working_tree(wd: Union[str, Path]) -> bool:
    return _git_rev_parse("--show-toplevel", Path(wd)) is not None


def get_git_root(wd: Optional[Union[str, Path]] = None) -> Path:
    """
    Fetches the root of the git repo.
    This corresponds to the root directory in the case of a working tree,
    or the `.git/` directory in the case of a quarantine during pre-receive.

    :param wd: working directory, defaults to None
    :return: absolute path to the git root, as a string.
    """
    if wd is None:
        wd = Path.cwd()
    else:
        wd = Path(wd)
    check_git_dir(wd)
    top_level = _git_rev_parse(option="--show-toplevel", wd=wd)
    if top_level is not None:
        return Path(top_level)
    root = _git_rev_parse(option="--git-dir", wd=wd)
    if root is None:
        raise NotAGitDirectory()
    return Path(root).resolve()


def check_git_dir(wd: Optional[Union[str, Path]] = None) -> None:
    """Check if folder is git directory."""
    if wd is None:
        wd = Path.cwd()
    if not is_git_dir(wd):
        raise NotAGitDirectory()


def git(
    command: List[str],
    timeout: int = COMMAND_TIMEOUT,
    check: bool = True,
    cwd: Optional[Union[str, Path]] = None,
    log_stderr: bool = True,
    ignore_git_config: bool = True,
) -> str:
    """Calls git with the given arguments, returns stdout as a string"""
    env = os.environ.copy()
    # Ensure git messages are in English
    env["LANG"] = "C"
    # Ensure git behavior is not affected by the user git configuration, but give us a
    # way to set some configuration (useful for safe.directory)
    if ignore_git_config:
        env["GIT_CONFIG_GLOBAL"] = os.getenv("GG_GIT_CONFIG", "")
        env["GIT_CONFIG_SYSTEM"] = ""

    if cwd is None:
        cwd = Path.cwd()

    try:
        logger.debug("command=%s timeout=%d", command, timeout)
        result = subprocess.run(
            (
                [
                    _get_git_path(),
                    "-c",
                    "core.quotePath=false",
                    "-c",
                    "safe.directory=*",
                ]
                + (
                    ["-c", "core.longpaths=true"]
                    if platform.system() == "Windows"
                    else []
                )
                + command
            ),
            check=check,
            capture_output=True,
            timeout=timeout,
            env=env,
            cwd=str(cwd),
        )
        if result.stderr and log_stderr:
            logger.warning(
                "command=%s, stderr=%s",
                command,
                result.stderr.decode("utf-8", errors="ignore"),
            )
        return result.stdout.decode("utf-8", errors="ignore").rstrip()
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="ignore")
        if log_stderr:
            logger.error("command=%s, stderr=%s", command, stderr)
        if "detected dubious ownership in repository" in stderr:
            raise GitError(
                "Git command failed because of a dubious ownership in repository.\n"
                "If you still want to run ggshield, make sure you mark "
                "the current repository as safe for git with:\n"
                "   git config --global --add safe.directory <YOUR_REPO>"
            )
        raise exc
    except subprocess.TimeoutExpired:
        raise GitCommandTimeoutExpired(
            'Command "{}" timed out'.format(" ".join(command))
        )


def git_ls(wd: Optional[Union[str, Path]] = None) -> List[str]:
    cmd = ["ls-files", "--recurse-submodules"]
    return git(cmd, timeout=600, cwd=wd).split("\n")


def _get_submodules_paths(wd: Optional[Union[str, Path]] = None) -> List[str]:
    cmd = ["submodule", "status"]
    return [
        submodule.split()[1]
        for submodule in git(cmd, timeout=600, cwd=wd).splitlines()
        if submodule
    ]


def git_ls_unstaged(wd: Optional[Union[str, Path]] = None) -> List[str]:
    # git command to get list of unstaged files in repo
    cmd = ["ls-files", "--others", "--exclude-standard"]
    unstaged_files = git(cmd, timeout=600, cwd=wd).splitlines()

    # --recurse-submodules is not compatible with --others so we
    # need to iterate over submodules to get the list of unstaged files
    for submodule in _get_submodules_paths(wd=wd):
        unstaged_files.extend(
            str(Path(submodule) / unstaged_file)
            for unstaged_file in git_ls_unstaged(
                wd=wd / Path(submodule) if wd else Path(submodule)
            )
        )
    return unstaged_files


def is_valid_git_commit_ref(ref: str, wd: Optional[Union[str, Path]] = None) -> bool:
    """
    Check if a reference is valid and can be resolved to a commit
    """
    if not wd:
        wd = Path.cwd()

    ref += "^{commit}"
    cmd = ["cat-file", "-e", ref]

    try:
        git(cmd, cwd=wd)
    except subprocess.CalledProcessError:
        return False

    return True


def check_git_ref(ref: str, wd: Optional[Union[str, Path]] = None) -> None:
    """Check if folder is a git repository and ref is a git reference."""
    if wd is None:
        wd = Path.cwd()
    check_git_dir(wd)

    if not is_valid_git_commit_ref(ref=ref, wd=wd):
        raise InvalidGitRefError(ref)


def get_list_commit_SHA(
    commit_range: str, max_count: Optional[int] = None
) -> List[str]:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    :param max_count: If set, limits the number of SHA returned to this amount. This
    returns the *end* of the list, so max_count=3 returns [HEAD~2, HEAD~1, HEAD].
    """

    cmd = ["rev-list", "--reverse", *commit_range.split()]
    if max_count is not None:
        cmd.extend(["--max-count", str(max_count)])
    # Makes rev-list print "bad revision" instead of telling the range is ambiguous
    cmd.append("--")

    try:
        commit_list = git(cmd).split("\n")
    except subprocess.CalledProcessError as e:
        if b"bad revision" in e.stderr and "~1.." in commit_range:
            # We got asked to list commits for A~1...B. If A~1 does not exist, but A
            # does, then return A and its descendants until B.
            a_ref, remaining = commit_range.split("~1", maxsplit=1)
            if not is_valid_git_commit_ref(f"{a_ref}~1") and is_valid_git_commit_ref(
                a_ref
            ):
                commit_range = a_ref + remaining
                return [a_ref] + get_list_commit_SHA(commit_range)
        return []

    if "" in commit_list:
        commit_list.remove("")
        # only happens when git rev-list doesn't error
        # but returns an empty range, example git rev-list HEAD...

    return commit_list


def get_last_commit_sha_of_branch(branch_name: str) -> Optional[str]:
    """
    Returns the last commit sha of the given branch, or None
    if no commit could be found
    """
    # The branch is not directly available in CI env
    # We need to get commits through remotes
    last_target_commit = get_list_commit_SHA(branch_name, max_count=1)

    # Unable to find a commit on this branch
    # Consider it empty
    if not last_target_commit:
        return None

    return last_target_commit[0]


def get_repository_url_from_path(wd: Path) -> Optional[str]:
    """
    Returns one of the repository remote urls. Returns None if no remote are found,
    or the directory is not a repository or we don't have git so we can't know if the
    directory is a repository.
    """
    try:
        if not is_git_available() or not is_git_dir(wd):
            return None
        remotes_raw = git(["remote", "-v"], cwd=wd).splitlines()
    except (subprocess.CalledProcessError, OSError):
        return None

    url: Optional[str] = None
    for line in remotes_raw:
        if match := re.search(r"^(.*)\t(.*) \(fetch\)$", line):
            name, url = match.groups()
            if name == "origin":
                break
    return simplify_git_url(url) if url else None


def get_filepaths_from_ref(
    ref: str, wd: Optional[Union[str, Path]] = None
) -> List[Path]:
    """
    Fetches a list of all file paths indexed at a given reference in a git repository.
    :param ref: git reference, like a commit SHA, a relative reference like HEAD~1, ...
    :param wd: string path to the git repository. Defaults to current directory
    """
    if not wd:
        wd = Path.cwd()

    check_git_ref(ref, wd)

    filepaths = git(
        ["ls-tree", "--name-only", "--full-name", "-r", ref], cwd=wd
    ).splitlines()
    return [Path(path_str) for path_str in filepaths]


def get_staged_filepaths(wd: Optional[Union[str, Path]] = None) -> List[Path]:
    """
    Fetches a list of all file paths at the index in a git repository.
    :param wd: string path to the git repository. Defaults to current directory
    """
    if not wd:
        wd = Path.cwd()

    filepaths = git(["ls-files", "--full-name", "-c"], cwd=wd).splitlines()
    return [Path(path_str) for path_str in filepaths]


@lru_cache(None)
def read_git_file(ref: str, path: Path, wd: Optional[Union[str, Path]] = None) -> str:
    # Use as_posix to handle git and Windows
    return git(["show", f"{ref}:{path.as_posix()}"], cwd=wd)


def get_remotes(wd: Optional[Union[str, Path]] = None) -> List[str]:
    """List all configured git remotes."""
    if not wd:
        wd = Path.cwd()
    return git(["remote"], cwd=wd).splitlines()


def get_default_branch(wd: Optional[Union[str, Path]] = None) -> str:
    """
    Return the default branch of the repository.

    Try to get the default branch from a remote, either origin or the first remote,
    otherwise return the config init.defaultBranch.
    """
    if not wd:
        wd = Path.cwd()

    remotes = get_remotes(wd)
    remote = None
    if "origin" in remotes:
        remote = "origin"
    elif len(remotes) > 0:
        remote = remotes[0]

    default_branch = None
    if remote is not None:
        for line in git(["remote", "show", remote], cwd=wd).splitlines():
            line = line.strip()
            if line.startswith("HEAD branch: "):
                default_branch = remote + "/" + line[len("HEAD branch: ") :]
                break

    if default_branch is None:
        return git(["config", "init.defaultBranch"], cwd=wd).strip()

    return default_branch
