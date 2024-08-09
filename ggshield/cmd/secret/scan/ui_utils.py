from pathlib import Path
from typing import List

from ggshield.core.scan import Scannable
from ggshield.core.text_utils import display_heading, display_info


def print_file_list(files: List[Scannable], binary_paths: List[Path]) -> None:
    if binary_paths:
        display_heading("Ignored binary files")
        for path in binary_paths:
            display_info(f"- {path}")
    display_heading("Files to scan")
    for f in files:
        display_info(f"- {f.path}")
