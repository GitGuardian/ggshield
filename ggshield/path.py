import os
import re
from pathlib import Path
from typing import Iterable, List, Set, Union

import click

from ggshield.git_shell import git_ls, is_git_dir

from .config import MAX_FILE_SIZE
from .filter import is_filepath_excluded
from .scan import File, Files


BINARY_FILE_EXTENSIONS = (".tar", ".xz", ".gz")


def get_files_from_paths(
    paths: List[str],
    exclusion_regexes: Set[re.Pattern],
    recursive: bool,
    yes: bool,
    verbose: bool,
    ignore_git: bool = False,
) -> Files:
    """
    Create a scan object from files content.

    :param paths: List of file/dir paths from the command
    :param paths_ignore: List of file/dir paths to ignore (glob pattern)
    :param recursive: Recursive option
    :param yes: Skip confirmation option
    :param verbose: Option that displays filepaths as they are scanned
    :param ignore_git: Ignore that the folder is a git repository
    """
    filepaths = get_filepaths(
        paths, exclusion_regexes, recursive, ignore_git=ignore_git
    )
    files = list(generate_files_from_paths(filepaths, verbose))

    if verbose:
        for f in files:
            click.echo(f"- {click.format_filename(f.filename)}")

    size = len(files)
    if size > 1 and not yes:
        click.confirm(
            f"{size} files will be scanned. Do you want to continue?", abort=True
        )

    return Files(files)


def get_filepaths(
    paths: Union[List, str],
    exclusion_regexes: Set[re.Pattern],
    recursive: bool,
    ignore_git: bool,
) -> Set[str]:
    """
    Retrieve the filepaths from the command.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :param ignore_git: Ignore that the folder is a git repository
    :raise: click.FileError if directory is given without --recursive option
    """
    targets = set()
    for path in paths:
        if os.path.isfile(path):
            targets.add(path)
        elif os.path.isdir(path):
            if not recursive:
                raise click.FileError(
                    click.format_filename(path), "Use --recursive to scan directories."
                )
            top_dir = Path(path)

            if is_git_dir(path) and not ignore_git:
                _targets = {os.path.join(path, target) for target in git_ls(path)}
            else:
                _targets = {str(target) for target in top_dir.rglob(r"*")}

            for file_path in _targets:
                if not is_filepath_excluded(file_path, exclusion_regexes):
                    targets.add(file_path)
    return targets


def generate_files_from_paths(paths: Iterable[str], verbose: bool) -> Iterable[File]:
    """Generate a list of scannable files from a list of filepaths."""
    for path in paths:
        if os.path.isdir(path) or not os.path.exists(path):
            continue

        file_size = os.path.getsize(path)
        if file_size > MAX_FILE_SIZE:
            if verbose:
                click.echo(f"ignoring file over 1MB: {path}")
            continue
        if path.endswith(BINARY_FILE_EXTENSIONS):
            if verbose:
                click.echo(f"ignoring binary file extension: {path}")
            continue
        with open(path, "r") as file:
            try:
                content = file.read()
                if content:
                    yield File(content, file.name, file_size)
            except UnicodeDecodeError:
                pass
