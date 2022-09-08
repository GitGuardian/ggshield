import os
import re
from pathlib import Path
from typing import Iterable, Iterator, List, Set, Union

import click
from pygitguardian.config import DOCUMENT_SIZE_THRESHOLD_BYTES

from ggshield.core.binary_extensions import BINARY_EXTENSIONS
from ggshield.core.filter import is_filepath_excluded
from ggshield.core.git_shell import git_ls, is_git_dir
from ggshield.scan import File, Files


DOCUMENT_SIZE_THRESHOLD_MBYTES = DOCUMENT_SIZE_THRESHOLD_BYTES // (1024 * 1024)


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
            click.echo(f"- {click.format_filename(f.filename)}", err=True)

    size = len(files)
    if size > 1 and not yes:
        click.confirm(
            f"{size} files will be scanned. Do you want to continue?",
            abort=True,
            err=True,
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

            if not ignore_git and is_git_dir(path):
                _targets = {os.path.join(path, target) for target in git_ls(path)}
            else:
                _targets = {str(target) for target in top_dir.rglob(r"*")}

            for file_path in _targets:
                if not is_filepath_excluded(file_path, exclusion_regexes):
                    targets.add(file_path)
    return targets


def is_path_binary(path: str) -> bool:
    _, ext = os.path.splitext(path)
    # `[1:]` because `ext` starts with a "." but extensions in `BINARY_EXTENSIONS` do not
    return ext[1:] in BINARY_EXTENSIONS


def generate_files_from_paths(paths: Iterable[str], verbose: bool) -> Iterator[File]:
    """Loop on filepaths and return an iterator on scannable files."""
    for path in paths:
        if os.path.isdir(path) or not os.path.exists(path):
            continue

        if is_path_binary(path):
            if verbose:
                click.echo(
                    f"ignoring binary file: {path}",
                    err=True,
                )
            continue

        file_size = os.path.getsize(path)
        if file_size > DOCUMENT_SIZE_THRESHOLD_BYTES:
            if verbose:
                click.echo(
                    f"ignoring file over {DOCUMENT_SIZE_THRESHOLD_MBYTES} MB: {path}",
                    err=True,
                )
            continue

        if file_size == 0:
            if verbose:
                click.echo(
                    f"ignoring empty file: {path}",
                    err=True,
                )
            continue

        yield File.from_path(path)
