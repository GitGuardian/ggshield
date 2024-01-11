import re
from pathlib import Path, PurePosixPath
from typing import List, Set, Union

from ggshield.utils._binary_extensions import BINARY_EXTENSIONS
from ggshield.utils.git_shell import get_filepaths_from_ref, git_ls, is_git_dir


class UnexpectedDirectoryError(ValueError):
    """Raise when a directory is used where it is not excepted"""

    def __init__(self, path: Path):
        self.path = path


def is_filepath_excluded(
    filepath: Union[str, Path], exclusion_regexes: Set[re.Pattern]
) -> bool:
    filepath = Path(filepath)
    return any(r.search(str(PurePosixPath(filepath))) for r in exclusion_regexes)


def get_filepaths(
    paths: List[Path],
    exclusion_regexes: Set[re.Pattern],
    recursive: bool,
    ignore_git: bool,
    ignore_git_staged: bool = False,
) -> Set[Path]:
    """
    Retrieve the filepaths from the command.

    :param paths: List of file/dir paths from the command
    :param recursive: Recursive option
    :param ignore_git: Ignore that the folder is a git repository
    :raise: UnexpectedDirectoryError if directory is given without --recursive option
    """
    targets: Set[Path] = set()
    for path in paths:
        if path.is_file():
            targets.add(path)
        elif path.is_dir():
            if not recursive:
                raise UnexpectedDirectoryError(path)

            if not ignore_git and is_git_dir(path):
                target_filepaths = (
                    get_filepaths_from_ref("HEAD", wd=path)
                    if ignore_git_staged
                    else git_ls(path)
                )
                _targets = {path / x for x in target_filepaths}
            else:
                _targets = path.rglob(r"*")

            for file_path in _targets:
                if not is_filepath_excluded(file_path, exclusion_regexes):
                    targets.add(file_path)
    return targets


def is_path_binary(path: Union[str, Path]) -> bool:
    ext = Path(path).suffix
    # `[1:]` because `ext` starts with a "." but extensions in `BINARY_EXTENSIONS` do not
    return ext[1:] in BINARY_EXTENSIONS
