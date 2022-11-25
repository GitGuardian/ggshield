import logging
import os
import subprocess
from functools import lru_cache
from shutil import which
from typing import Any, List, Optional

import click
from click import UsageError

from ggshield.core.errors import UnexpectedError


COMMAND_TIMEOUT = 45

logger = logging.getLogger(__name__)


@lru_cache(None)
def get_git_path(cwd: str) -> str:
    git_path = which("git")

    if git_path is None:
        raise Exception("unable to find git executable in PATH/PATHEXT")

    # lower()ing these would provide additional coverage on case-
    # insensitive filesystems but detection is problematic
    git_path = os.path.abspath(git_path)
    cwd = os.path.abspath(cwd)
    path_env = [
        os.path.abspath(p) for p in os.environ.get("PATH", "").split(os.pathsep)
    ]

    # git was found - ignore git in cwd if cwd not in PATH
    if cwd == os.path.dirname(git_path) and cwd not in path_env:
        raise Exception("rejecting git executable in CWD not in PATH")

    return git_path


GIT_PATH = get_git_path(os.getcwd())


@lru_cache(None)
def is_git_dir(wd: str) -> bool:
    check_git_installed()
    cmd = [GIT_PATH, "-C", wd, "status"]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def check_git_dir(wd: Optional[str] = None) -> None:
    """Check if folder is git directory."""
    if wd is None:
        wd = os.getcwd()
    if not is_git_dir(wd):
        raise UsageError("Not a git directory.")


def get_git_root(wd: Optional[str] = None) -> str:
    cmd = [GIT_PATH]
    if wd is not None:
        cmd.extend(("-C", wd))

    cmd.extend(("rev-parse", "--show-toplevel"))
    return shell(cmd)


@lru_cache(None)
def check_git_installed() -> None:
    """Check if git is installed."""
    with subprocess.Popen(
        [GIT_PATH, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise UnexpectedError("Git is not installed.")


def shell(
    command: List[str],
    timeout: int = COMMAND_TIMEOUT,
    check: bool = False,
) -> str:
    """Execute a command in a subprocess."""
    env = os.environ.copy()
    env["LANG"] = "C"

    try:
        logger.debug("command=%s", command)
        result = subprocess.run(
            command,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
        return result.stdout.decode("utf-8", errors="ignore").rstrip()
    except subprocess.TimeoutExpired:
        raise click.Abort('Command "{}" timed out'.format(" ".join(command)))


def shell_split(command: List[str], **kwargs: Any) -> List[str]:
    return shell(command, **kwargs).split("\n")


def git(command: List[str], timeout: int = COMMAND_TIMEOUT, check: bool = True) -> str:
    """Calls git with the given arguments, returns stdout as a string"""
    return shell([GIT_PATH] + command, timeout=timeout, check=check)


def git_ls(wd: Optional[str] = None) -> List[str]:
    cmd = [GIT_PATH]
    if wd is not None:
        cmd.extend(("-C", wd))

    cmd.extend(("ls-files", "--recurse-submodules"))

    return shell_split(cmd, timeout=600)


def is_valid_git_commit_ref(ref: str) -> bool:
    """
    Check if a reference is valid and can be resolved to a commit
    """
    ref += "^{commit}"
    cmd = [GIT_PATH, "cat-file", "-e", ref]

    try:
        shell(cmd, check=True)
    except subprocess.CalledProcessError:
        return False

    return True


def get_list_commit_SHA(
    commit_range: str, max_count: Optional[int] = None
) -> List[str]:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    :param max_count: If set, limits the number of SHA returned to this amount. This
    returns the *end* of the list, so max_count=3 returns [HEAD~2, HEAD~1, HEAD].
    """

    cmd = [GIT_PATH, "rev-list", "--reverse", *commit_range.split()]
    if max_count is not None:
        cmd.extend(["--max-count", str(max_count)])
    # Makes rev-list print "bad revision" instead of telling the range is ambiguous
    cmd.append("--")

    try:
        commit_list = shell_split(cmd, check=True)
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
