from enum import Enum, auto
from pathlib import Path, PurePath, PurePosixPath
from typing import List, Pattern, Set, Tuple, Union
from urllib.parse import quote

from ggshield.utils._binary_extensions import BINARY_EXTENSIONS
from ggshield.utils.git_shell import (
    get_filepaths_from_ref,
    git_ls,
    git_ls_unstaged,
    is_git_dir,
)


class InvalidPathError(Exception):
    """Raised when a path argument is invalid (does not exist, etc.)."""

    pass


def expand_path_args(raw_paths: Tuple[str, ...]) -> List[Path]:
    """Expand ``@file`` arguments into real paths.

    Each element of *raw_paths* is either a literal path or a ``@file``
    reference.  When a ``@file`` reference is encountered the referenced file
    is read and each non-blank line is treated as a path.  All resulting paths
    are resolved and validated for existence.

    Raises :class:`InvalidPathError` if any path is invalid.
    """
    expanded: List[Path] = []
    for raw in raw_paths:
        if raw.startswith("@"):
            list_file = Path(raw[1:])
            if not list_file.is_file():
                raise InvalidPathError(
                    f"Path list file '{list_file}' does not exist or is not a file."
                )
            for line_no, line in enumerate(list_file.read_text().splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                p = Path(line).resolve()
                if not p.exists():
                    raise InvalidPathError(
                        f"In '{list_file}', line {line_no}: "
                        f"path '{line}' does not exist."
                    )
                expanded.append(p)
        else:
            p = Path(raw).resolve()
            if not p.exists():
                raise InvalidPathError(f"Path '{raw}' does not exist.")
            expanded.append(p)
    if not expanded:
        raise InvalidPathError("No paths provided.")
    return expanded


class ListFilesMode(Enum):
    """
    Control `get_filepaths()` behavior:

    - ALL: list all specified paths. If one of the path is a directory, list all its paths recursively.
    - ALL_BUT_GITIGNORED: like ALL, except those ignored by git (listed in .gitignore).
    - GIT_COMMITTED_OR_STAGED: list all committed files and all staged files.
    - GIT_COMMITTED: list only committed files.
    """

    GIT_COMMITTED = auto()
    GIT_COMMITTED_OR_STAGED = auto()
    ALL_BUT_GITIGNORED = auto()
    ALL = auto()


def is_path_excluded(
    path: Union[str, Path], exclusion_regexes: Set[Pattern[str]]
) -> bool:
    path = Path(path)
    if path.is_dir():
        # The directory exclusion regexes have to end with a slash
        # To check if path is excluded, we need to add a trailing slash
        path_string = f"{PurePosixPath(path)}/"
    else:
        path_string = str(PurePosixPath(path))
    return any(r.search(path_string) for r in exclusion_regexes)


def list_files(
    paths: List[Path],
    exclusion_regexes: Set[Pattern[str]],
    list_files_mode: ListFilesMode,
) -> Set[Path]:
    """
    Retrieve a set of the files inside `paths`.

    Note: only plain files are returned, not directories.
    """
    targets: Set[Path] = set()
    for path in paths:
        if path.is_file():
            if (
                list_files_mode == ListFilesMode.ALL_BUT_GITIGNORED
                and is_git_dir(path.parent)
                and path.name not in git_ls_unstaged(path.parent) + git_ls(path.parent)
            ):
                continue
            targets.add(path)
        elif path.is_dir():
            _targets = set()
            if list_files_mode != ListFilesMode.ALL and is_git_dir(path):
                target_filepaths = (
                    get_filepaths_from_ref("HEAD", wd=path)
                    if list_files_mode == ListFilesMode.GIT_COMMITTED
                    else git_ls(path)
                )
                _targets = {path / x for x in target_filepaths}
                if list_files_mode == ListFilesMode.ALL_BUT_GITIGNORED:
                    _targets.update({path / x for x in git_ls_unstaged(path)})
            else:
                _targets = path.rglob(r"*")

            for file_path in _targets:
                if not file_path.is_dir() and not is_path_excluded(
                    file_path, exclusion_regexes
                ):
                    targets.add(file_path)
    return targets


def is_path_binary(path: Union[str, Path]) -> bool:
    ext = Path(path).suffix
    # `[1:]` because `ext` starts with a "." but extensions in `BINARY_EXTENSIONS` do not
    return ext[1:] in BINARY_EXTENSIONS


def url_for_path(path: PurePath) -> str:
    if not path.is_absolute():
        return quote(path.as_posix())

    # Allow ':'. This is required to represent the Windows drive in an URL.
    path_str = quote(path.as_posix(), safe="/:")
    if path_str[0] == "/":
        return f"file://{path_str}"
    else:
        # This happens for Windows paths: `path_str` is something like "c:/foo/bar"
        return f"file:///{path_str}"
