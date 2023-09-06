from pathlib import Path
from typing import Any

import click


class RealPath(click.Path):
    """
    A click.Path which uses real Path objects
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, path_type=Path, **kwargs)
