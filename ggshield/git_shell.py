import subprocess
from typing import List

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


def shell(command: str) -> List:
    """ Execute a command in a subprocess. """
    return (
        subprocess.check_output(command.split(" ")).decode("utf-8").rstrip().split("\n")
    )
