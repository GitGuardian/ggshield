import subprocess
from typing import List, Optional

import click


def is_git_dir():
    try:
        check_git_dir()
        return True
    except click.ClickException:
        return False


def check_git_dir():
    """ Check if folder is git directory. """
    check_git_installed()
    with subprocess.Popen(
        ["git", "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Not a git directory.")


def check_git_installed():
    """ Check if git is installed. """
    with subprocess.Popen(
        ["git", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Git is not installed.")


def shell(command: List[str]) -> List:
    """ Execute a command in a subprocess. """
    try:
        result = subprocess.run(command, check=True, capture_output=True)
        output = result.stdout.decode("utf-8").rstrip().split("\n")
        return output
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    except Exception as exc:
        raise click.ClickException("unhandled exception: {}".format(str(exc)))

    return []


def get_list_commit_SHA(commit_range: Optional[str], all_commits: bool) -> List[str]:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    """

    if all_commits:
        return shell(["git", "rev-list", "--reverse", "--all"])

    return shell(["git", "rev-list", "--reverse", commit_range])
