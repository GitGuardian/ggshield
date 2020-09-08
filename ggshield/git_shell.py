import os
import subprocess
from functools import lru_cache
from shutil import which
from typing import Any, List, Optional

import click


COMMAND_TIMEOUT = 45


@lru_cache(None)
def get_git_path(cwd: str) -> str:
    git_path = str(which("git"))

    if cwd in git_path and cwd not in os.environ.get("PATH", "").split(os.pathsep):
        raise Exception("unable to find git executable in PATH/PATHEXT")

    return git_path


GIT_PATH = get_git_path(os.getcwd())


def is_git_dir(wd: Optional[str] = None) -> bool:
    try:
        check_git_dir(wd)
        return True
    except click.ClickException:
        return False


@lru_cache(None)
def check_git_dir(wd: Optional[str] = None) -> None:
    """ Check if folder is git directory. """
    check_git_installed()

    cmd = [GIT_PATH]
    if wd is not None:
        cmd.extend(("-C", wd))

    cmd.append("status")
    with subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Not a git directory.")


@lru_cache(None)
def get_git_root(wd: Optional[str] = None) -> str:
    cmd = [GIT_PATH]
    if wd is not None:
        cmd.extend(("-C", wd))

    cmd.extend(("rev-parse", "--show-toplevel"))
    return shell(cmd)


@lru_cache(None)
def check_git_installed() -> None:
    """ Check if git is installed. """
    with subprocess.Popen(
        [GIT_PATH, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Git is not installed.")


def shell(command: List[str], timeout: int = COMMAND_TIMEOUT) -> str:
    """ Execute a command in a subprocess. """
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return result.stdout.decode("utf-8").rstrip()
    except subprocess.CalledProcessError:
        pass
    except subprocess.TimeoutExpired:
        raise click.Abort('Command "{}" timed out'.format(" ".join(command)))
    except Exception as exc:
        raise click.ClickException(f"Unhandled exception: {str(exc)}")

    return ""


def shell_split(command: List[str], **kwargs: Any) -> List[str]:
    return shell(command, **kwargs).split("\n")


def git_ls(wd: Optional[str] = None) -> List[str]:
    cmd = [GIT_PATH]
    if wd is not None:
        cmd.extend(("-C", wd))

    cmd.extend(("ls-files", "--recurse-submodules"))

    return shell_split(cmd, timeout=600)


def get_list_commit_SHA(commit_range: str) -> List[str]:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    """

    commit_list = shell_split(
        [GIT_PATH, "rev-list", "--reverse", *commit_range.split()]
    )
    if "" in commit_list:
        commit_list.remove("")
        # only happens when git rev-list doesn't error
        # but returns an empty range, example git rev-list HEAD...

    return commit_list
