import os
import re
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set

import click

from ggshield.core.file_utils import get_filepaths, is_path_binary

from .scannable import Files, Scannable


class File(Scannable):
    """Implementation of Scannable for files from the disk."""

    def __init__(self, path: str):
        super().__init__()
        self._path = Path(path)
        self._content: Optional[str] = None
        self._utf8_encoded_size: Optional[int] = None

    @property
    def url(self) -> str:
        return f"file://{self._path.absolute().as_posix()}"

    @property
    def filename(self) -> str:
        return str(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def is_longer_than(self, max_utf8_encoded_size: int) -> bool:
        if self._utf8_encoded_size is not None:
            # We already have the encoded size, easy
            return self._utf8_encoded_size > max_utf8_encoded_size

        with self.path.open("rb") as fp:
            (
                result,
                self._content,
                self._utf8_encoded_size,
            ) = Scannable._is_file_longer_than(fp, max_utf8_encoded_size)
        return result

    @property
    def content(self) -> str:
        if self._content is None:
            with self.path.open("rb") as f:
                self._content, self._utf8_encoded_size = Scannable._decode_bytes(
                    f.read()
                )
        return self._content


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


def generate_files_from_paths(
    paths: Iterable[str], verbose: bool
) -> Iterator[Scannable]:
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

        yield File(path)
