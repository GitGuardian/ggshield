import re
from pathlib import Path
from typing import Iterable, Iterator, List, Set, Union

import click

from ggshield.utils.files import UnexpectedDirectoryError, get_filepaths, is_path_binary

from .scannable import Scannable


class File(Scannable):
    """Implementation of Scannable for files from the disk."""

    def __init__(self, path: Union[str, Path]):
        super().__init__()
        self._path = Path(path)

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

    def _read_content(self) -> None:
        if self._content is None:
            with self.path.open("rb") as f:
                self._content, self._utf8_encoded_size = Scannable._decode_bytes(
                    f.read()
                )


def get_files_from_paths(
    paths: List[Path],
    exclusion_regexes: Set[re.Pattern],
    recursive: bool,
    yes: bool,
    display_scanned_files: bool,
    display_binary_files: bool,
    ignore_git: bool = False,
    ignore_git_staged: bool = False,
) -> List[Scannable]:
    """
    Create a scan object from files content.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :param yes: Skip confirmation option
    :param display_scanned_files: In some parts of the code (e.g. SCA), we might want
    to display a processed list instead and set this to False
    :param display_binary_files: Display all ignored binary files
    :param ignore_git: Ignore that the folder is a git repository
    """
    try:
        filepaths = get_filepaths(
            paths,
            exclusion_regexes,
            recursive,
            ignore_git=ignore_git,
            ignore_git_staged=ignore_git_staged,
        )
    except UnexpectedDirectoryError as error:
        raise click.UsageError(
            f"{click.format_filename(error.path)} is a directory."
            " Use --recursive to scan directories."
        )

    files = list(generate_files_from_paths(filepaths, display_binary_files))

    if display_scanned_files:
        for f in files:
            click.echo(f"- {click.format_filename(f.filename)}", err=True)

    size = len(files)
    if size > 1 and not yes:
        click.confirm(
            f"{size} files will be scanned. Do you want to continue?",
            abort=True,
            err=True,
        )

    return files


def generate_files_from_paths(
    paths: Iterable[Path], display_binary_files: bool
) -> Iterator[Scannable]:
    """Loop on filepaths and return an iterator on scannable files."""
    for path in paths:
        if path.is_dir() or not path.exists():
            continue

        if is_path_binary(path):
            if display_binary_files:
                click.echo(
                    f"ignoring binary file: {path}",
                    err=True,
                )
            continue

        yield File(path)
