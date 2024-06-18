from pathlib import Path
from typing import Pattern, Set

from click import UsageError

from ggshield.utils.files import is_path_excluded


def check_directory_not_ignored(directory: Path, exclusion_regexes: Set[Pattern[str]]):
    if is_path_excluded(directory.resolve(), exclusion_regexes):
        raise UsageError("An ignored file or directory cannot be scanned.")
