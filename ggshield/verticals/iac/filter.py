from pathlib import Path
from typing import List, Pattern, Set

from ggshield.utils.files import ListFilesMode, is_path_binary, list_files


IAC_EXTENSIONS = {
    ".json",
    ".yml",
    ".yaml",
    ".jinja",
    ".py.schema",
    ".jinja.schema",
    ".tf",
}
IAC_FILENAME_KEYWORDS = {"tfvars", "dockerfile"}


def get_iac_files_from_path(
    path: Path,
    exclusion_regexes: Set[Pattern[str]],
    ignore_git: bool = False,
    ignore_git_staged: bool = False,
) -> List[Path]:
    """
    Returns IaC file paths found recursively in a given directory.

    :param path: root directory
    :param exclusion_regexes: Patterns to exclude from the files
    :param verbose: Option that displays filepaths as they are scanned
    :param ignore_git: Ignore that the folder is a git repository. If False, only files added to git are scanned
    """
    paths = list_files(
        paths=[path],
        exclusion_regexes=exclusion_regexes,
        list_files_mode=(
            ListFilesMode.ALL
            if ignore_git
            else (
                ListFilesMode.GIT_COMMITTED
                if ignore_git_staged
                else ListFilesMode.GIT_COMMITTED_OR_STAGED
            )
        ),
    )
    return [x for x in paths if is_iac_file_path(x)]


def is_iac_file_path(path: Path) -> bool:
    if is_path_binary(path):
        return False
    if any(ext in IAC_EXTENSIONS for ext in path.suffixes):
        return True
    if any(path.name.endswith(iac_ext) for iac_ext in IAC_EXTENSIONS):
        return True
    name = path.name.lower()
    return any(keyword in name for keyword in IAC_FILENAME_KEYWORDS)
