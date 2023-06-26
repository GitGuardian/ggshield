from pathlib import Path
from typing import Any, Optional

import click

from ggshield.core.text_utils import display_warning


def display_sca_beta_warning(func):
    """
    Displays warning about SCA commands being in beta.
    """

    def func_with_beta_warning(*args, **kwargs):
        display_warning(
            "This feature is still in beta, its behavior may change in future versions."
        )
        return func(*args, **kwargs)

    return func_with_beta_warning


@click.group()
@click.pass_context
def scan_group(*args, **kwargs: Any) -> None:
    """Perform a SCA scan."""


@scan_group.command(name="diff")
@click.argument(
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
)
@click.option(
    "--ref",
    metavar="REF",
    help="Git reference to compare working directory to.",
)
@click.option(
    "--staged",
    is_flag=True,
    help="Compare staged state instead of working state.",
)
@click.pass_context
@display_sca_beta_warning
def scan_diff_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    ref: str,
    **kwargs: Any,
) -> int:
    """
    Find SCA vulnerabilities in a git working directory, compared to git history.
    """
    return 0


@scan_group.command(name="all")
@click.pass_context
@display_sca_beta_warning
def scan_all_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan a directory for SCA vulnerabilities.
    """
    return 0
