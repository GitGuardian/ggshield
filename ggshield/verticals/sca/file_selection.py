import re
from pathlib import Path
from typing import List, Optional, Set

import click
from pygitguardian.client import GGClient
from pygitguardian.models import Detail

from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.scan import Scannable
from ggshield.core.scan.file import get_files_from_paths
from ggshield.core.tar_utils import INDEX_REF
from ggshield.core.text_utils import display_info
from ggshield.utils.files import is_filepath_excluded
from ggshield.utils.git_shell import get_filepaths_from_ref, get_staged_filepaths


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
    paths = [
        x.path
        for x in get_files_from_paths(
            paths=[path],
            exclusion_regexes=exclusion_regexes,
            recursive=True,
            yes=True,
            display_binary_files=verbose,
            display_scanned_files=False,  # If True, this displays all files in the directory but we only want SCA files
            ignore_git=ignore_git,
        )
        if is_not_excluded_from_sca(x)
    ]

    return [str(x.relative_to(path)) for x in paths]


def is_not_excluded_from_sca(scannable: Scannable) -> bool:
    """
    Returns True if file is in an SCA accepted path, which means that none of
    the directories of the path appear in SCA_IGNORE_LIST
    """
    return not any(part in SCA_IGNORE_LIST for part in scannable.path.parts)


def sca_files_from_git_repo(
    directory: Path,
    ref: str,
    client: GGClient,
    exclusion_regexes: Optional[Set[re.Pattern]] = None,
    verbose: bool = False,
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
            if not is_filepath_excluded(path, exclusion_regexes)
        ]
    )
    if isinstance(sca_files_result, Detail):
        if sca_files_result.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        elif sca_files_result.status_code == 501:
            raise UnexpectedError(sca_files_result.detail)
        raise UnexpectedError("Failed to select SCA files")

    sca_files = sca_files_result.sca_files
    if verbose:
        display_info(f"> Scanned files from {ref}:")
        for filename in sca_files:
            display_info(f"- {click.format_filename(filename)}")

    return set(map(Path, sca_files_result.sca_files))
