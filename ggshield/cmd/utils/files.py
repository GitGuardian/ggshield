import re
from pathlib import Path
from typing import Set

from click import UsageError

from ggshield.utils.files import is_filepath_excluded


IGNORED_ERROR_MESSAGE = "An ignored file or directory cannot be scanned."


def check_directory_not_ignored(exclusion_regexes: Set[re.Pattern]):
    if re.compile("(^|/)\\.$") in exclusion_regexes:
        raise UsageError(IGNORED_ERROR_MESSAGE)


def check_path_not_ignored(path: Path, exclusion_regexes: Set[re.Pattern]):
    if is_filepath_excluded(path, exclusion_regexes):
        raise UsageError(IGNORED_ERROR_MESSAGE)
