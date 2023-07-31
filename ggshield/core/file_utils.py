import os
import re
import tarfile
from io import BytesIO
from pathlib import Path
from typing import List, Set, Union

import click

from ggshield.core.binary_extensions import BINARY_EXTENSIONS
from ggshield.core.filter import is_filepath_excluded
from ggshield.core.git_shell import git_ls, is_git_dir


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
    :raise: click.UsageError if directory is given without --recursive option
    """
    targets = set()
    for path in paths:
        if os.path.isfile(path):
            targets.add(path)
        elif os.path.isdir(path):
            if not recursive:
                raise click.UsageError(
                    f"{click.format_filename(path)} is a directory. Use --recursive to scan directories."
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


def get_empty_tar() -> bytes:
    bytes = BytesIO()
    file = tarfile.open(fileobj=bytes, mode="w:gz")
    file.close()
    return bytes.getvalue()
