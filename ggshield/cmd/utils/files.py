import re
from pathlib import Path
from typing import Set

from click import UsageError

from ggshield.utils.files import is_filepath_excluded


def check_directory_not_ignored(directory: Path, exclusion_regexes: Set[re.Pattern]):
    if is_filepath_excluded(directory, exclusion_regexes):
        raise UsageError("An ignored file or directory cannot be scanned.")
