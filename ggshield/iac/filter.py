import re
from pathlib import Path
from typing import List, Set

from ggshield.core.file_utils import get_files_from_paths
from ggshield.scan import Scannable


IAC_EXTENSIONS = {
    ".json",
    ".yml",
    ".yaml",
    ".jinja",
    ".py",
    ".py.schema",
    ".jinja.schema",
    ".tf",
}
IAC_FILENAME_KEYWORDS = {"tfvars", "dockerfile"}


def get_iac_files_from_paths(
    path: Path,
    exclusion_regexes: Set[re.Pattern],
    verbose: bool,
    ignore_git: bool = False,
) -> List[str]:
    """
    Create a Files object from paths, ignoring non IAC files

    :param paths: List of file/dir paths from the command
    :param exclusion_regexes: Patterns to exclude from the files
    :param recursive: Recursive option
    :param yes: Skip confirmation option
    :param verbose: Option that displays filepaths as they are scanned
    :param ignore_git: Ignore that the folder is a git repository. If False, only files added to git are scanned
    """
    files = get_files_from_paths(
        paths=[str(path)],
        exclusion_regexes=exclusion_regexes,
        recursive=True,
        yes=True,
        verbose=verbose,
        ignore_git=ignore_git,
    ).apply_filter(is_file_iac_file)

    return [str(Path(x).relative_to(path)) for x in files.paths]


def is_file_iac_file(scannable: Scannable) -> bool:
    path = Path(scannable.filename)
    extensions = path.suffixes
    if any(ext in IAC_EXTENSIONS for ext in extensions):
        return True
    name = path.name.lower()
    return any(keyword in name for keyword in IAC_FILENAME_KEYWORDS)
