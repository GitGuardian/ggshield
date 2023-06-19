from pathlib import Path
from typing import Any, Optional

import click


@click.command()
@click.pass_context
def scan_diff_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan a git repository for SCA vulnerabilities.
    """
    return 0


@click.command()
@click.pass_context
def scan_full_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan a directory for SCA vulnerabilities.
    """
    return 0
