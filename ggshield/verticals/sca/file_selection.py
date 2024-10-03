import re
from pathlib import Path
from typing import List, Optional, Pattern, Set

import click
from pygitguardian.client import GGClient
from pygitguardian.models import Detail

from ggshield.core import ui
from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.tar_utils import INDEX_REF
from ggshield.utils.files import (
    ListFilesMode,
    is_path_binary,
    is_path_excluded,
    list_files,
)
from ggshield.utils.git_shell import get_filepaths_from_ref, get_staged_filepaths


# List of filepaths to ignore for SCA scans
SCA_EXCLUSION_REGEXES = {
    re.compile(re.escape(pattern) + "/.*")
    for pattern in (
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
}


def get_all_files_from_sca_paths(
    path: Path, exclusion_regexes: Set[Pattern[str]], ignore_git: bool = False
) -> List[str]:
    """
    Recurse on `path` and return a list of SCA paths.

    :param path: path to scan
    :param exclusion_regexes: list of regexes, used to exclude some filepaths
    :param ignore_git: Ignore that the folder is a git repository. If False, only files tracked by git are scanned
    """
    paths = list_files(
        paths=[path],
        exclusion_regexes=exclusion_regexes | SCA_EXCLUSION_REGEXES,
        list_files_mode=(
            ListFilesMode.ALL if ignore_git else ListFilesMode.GIT_COMMITTED_OR_STAGED
        ),
    )
    return sorted(str(x.relative_to(path)) for x in paths if not is_path_binary(x))


def sca_files_from_git_repo(
    directory: Path,
    ref: str,
    client: GGClient,
    exclusion_regexes: Optional[Set[Pattern[str]]] = None,
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
            if not is_path_excluded(path, exclusion_regexes)
        ]
    )
    if isinstance(sca_files_result, Detail):
        if sca_files_result.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        elif sca_files_result.status_code == 501:
            raise UnexpectedError(sca_files_result.detail)
        raise UnexpectedError("Failed to select SCA files")

    sca_files = sca_files_result.sca_files
    if ui.is_verbose():
        ui.display_verbose(f"> Scanned files from {ref}:")
        for filename in sca_files:
            ui.display_verbose(f"- {click.format_filename(filename)}")

    return set(map(Path, sca_files_result.sca_files))
