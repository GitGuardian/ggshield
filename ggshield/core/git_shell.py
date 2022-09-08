import logging
import os
import subprocess
from functools import lru_cache
from shutil import which
from typing import Any, List, Optional

import click


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
        raise click.ClickException("Not a git directory.")


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
            raise click.ClickException("Git is not installed.")


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


def get_list_commit_SHA(commit_range: str) -> List[str]:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    """
    try:
        commit_list = shell_split(
            [GIT_PATH, "rev-list", "--reverse", *commit_range.split(), "--"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        if b"bad revision" in e.stderr and commit_range.endswith("~1..."):
            # Handle the case where commit_ref has no parent
            commit_ref = commit_range[:-5]
            if is_valid_git_commit_ref(commit_ref):
                return [commit_ref] + get_list_commit_SHA(f"{commit_ref}...")
        return []

    if "" in commit_list:
        commit_list.remove("")
        # only happens when git rev-list doesn't error
        # but returns an empty range, example git rev-list HEAD...

    return commit_list
