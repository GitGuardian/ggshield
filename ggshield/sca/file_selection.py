import re
from pathlib import Path
from typing import List, Optional, Set

from pygitguardian.models import Detail

from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.filter import is_filepath_excluded
from ggshield.core.git_shell import (
    INDEX_REF,
    get_filepaths_from_ref,
    get_staged_filepaths,
)
from ggshield.sca.client import SCAClient
from ggshield.scan import Scannable
from ggshield.scan.file import get_files_from_paths


# List of filepaths to ignore for SCA scans

SCA_IGNORE_LIST = (
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "site-packages",
    ".idea",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".hypothesis",
)


def get_all_files_from_sca_paths(
    path: Path,
    exclusion_regexes: Set[re.Pattern],
    verbose: bool,
    ignore_git: bool = False,
) -> List[str]:
    """
    Create a Files object from a path, recursively, ignoring non SCA files

    :param path: path to scan
    :param exclusion_regexes: list of regexes, used to exclude some filepaths
    :param verbose: Option that displays filepaths as they are scanned
    :param ignore_git: Ignore that the folder is a git repository. If False, only files tracked by git are scanned
    """
    files = get_files_from_paths(
        paths=[str(path)],
        exclusion_regexes=exclusion_regexes,
        recursive=True,
        yes=True,
        verbose=verbose,
        ignore_git=ignore_git,
    ).apply_filter(is_not_excluded_from_sca)

    return [str(x.relative_to(path)) for x in files.paths]


def is_not_excluded_from_sca(scannable: Scannable) -> bool:
    """
    Returns True if file is in an SCA accepted path, which means that none of
    the directories of the path appear in SCA_IGNORE_LIST
    """
    return not any(part in SCA_IGNORE_LIST for part in scannable.path.parts)


def sca_files_from_git_repo(
    directory: Path,
    ref: str,
    client: SCAClient,
    exclusion_regexes: Optional[Set[re.Pattern]] = None,
) -> Set[Path]:
    """Returns SCA files from the git repository at
    the given directory, for the given ref. Empty string denotes selection
    from staging area."""
    exclusion_regexes = exclusion_regexes if exclusion_regexes is not None else set()

    if ref == INDEX_REF:
        all_files = get_staged_filepaths(wd=str(directory))
    else:
        all_files = get_filepaths_from_ref(ref, wd=str(directory))

    sca_files_result = client.compute_sca_files(
        files=[
            str(path)
            for path in all_files
            if not is_filepath_excluded(str(path), exclusion_regexes)
        ]
    )
    if isinstance(sca_files_result, Detail):
        if sca_files_result.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        raise UnexpectedError("Failed to select SCA files")

    return set(map(Path, sca_files_result.sca_files))
