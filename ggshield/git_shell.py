import subprocess
from typing import List

import click


COMMAND_TIMEOUT = 45
GIT_PATH = "git"


def is_git_dir() -> bool:
    try:
        check_git_dir()
        return True
    except click.ClickException:
        return False


def check_git_dir():
    """ Check if folder is git directory. """
    check_git_installed()
    with subprocess.Popen(
        [GIT_PATH, "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Not a git directory.")


def check_git_installed():
    """ Check if git is installed. """
    with subprocess.Popen(
        [GIT_PATH, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) as process:
        if process.wait():
            raise click.ClickException("Git is not installed.")


def shell(command: List[str]) -> List[str]:
    """ Execute a command in a subprocess. """
    try:
        result = subprocess.run(
            command, check=True, stdout=subprocess.PIPE, timeout=COMMAND_TIMEOUT
        )
        return result.stdout.decode("utf-8").rstrip().split("\n")
    except subprocess.CalledProcessError:
        pass
    except subprocess.TimeoutExpired:
        raise click.Abort('Command "{}" timed out'.format(" ".join(command)))
    except Exception as exc:
        raise click.ClickException(f"Unhandled exception: {str(exc)}")

    return []


def get_list_commit_SHA(commit_range: str) -> List[str]:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    """

    return shell([GIT_PATH, "rev-list", "--reverse", commit_range])


def get_list_all_commits() -> List[str]:
    return shell([GIT_PATH, "rev-list", "--reverse", "--all"])
