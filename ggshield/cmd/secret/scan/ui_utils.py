from pathlib import Path
from typing import List

from ggshield.core import ui
from ggshield.core.scan import Scannable


def print_file_list(files: List[Scannable], binary_paths: List[Path]) -> None:
    if not ui.is_verbose():
        return
    if binary_paths:
        ui.display_heading("Ignored binary files")
        for path in binary_paths:
            ui.display_verbose(f"- {path}")
    ui.display_heading("Files to scan")
    for f in files:
        ui.display_verbose(f"- {f.path}")
