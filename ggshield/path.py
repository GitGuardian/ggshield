import os
from pathlib import Path
from typing import Dict, Iterable, List, Pattern, Union

import click

from .git_shell import is_git_dir, shell
from .scannable import File, Files


def get_files_from_paths(
    paths: Union[Path, str],
    exclude_regex: Pattern[str],
    recursive: bool,
    yes: bool,
    verbose: bool,
) -> Files:
    """
    Create a scan object from files content.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :param yes: Skip confirmation option
    :param verbose: Option that displays filepaths as they are scanned
    """
    files = list(
        generate_files_from_paths(get_filepaths(paths, recursive), exclude_regex)
    )

    if verbose:
        for f in files:
            click.echo(f.filename)

    size = len(files)
    if size > 1 and not yes:
        click.confirm(
            "{} files will be scanned. Do you want to continue?".format(size),
            abort=True,
        )

    return Files(files)


def get_filepaths(paths: Union[List, str], recursive: bool) -> Iterable[Path]:
    """
    Retrieve the filepaths from the command.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :raise: click.FileError if directory is given without --recursive option
    """
    for path in paths:
        if os.path.isfile(path):
            yield path

        elif os.path.isdir(path):
            if not recursive:
                raise click.FileError(
                    click.format_filename(path), "Use --recursive to scan directories."
                )

            for root, dirs, sub_paths in os.walk(path):
                for sub_path in sub_paths:
                    yield root + "/" + sub_path


def generate_files_from_paths(
    paths: Iterable[Path], exclude_regex: Pattern[str]
) -> Iterable[Dict]:
    """ Generate a list of scannable files from a list of filepaths."""
    path_blacklist = (
        [
            "{}/{}".format(os.getcwd(), filename)
            for filename in shell("git ls-files -o -i --exclude-standard")
        ]
        if is_git_dir()
        else []
    )

    for path in paths:
        if exclude_regex and exclude_regex.search(path):
            continue

        if (path in path_blacklist) or path.startswith(
            "{}/{}".format(os.getcwd(), ".git/")
        ):
            continue

        with open(path, "r") as file:
            try:
                content = file.read()
                if content:
                    yield File(
                        content,
                        click.format_filename(file.name[len(os.getcwd()) + 1 :]),
                    )
            except UnicodeDecodeError:
                pass
