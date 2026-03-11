import shutil
from pathlib import Path
from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.core.errors import UnexpectedError

from .targets import TARGET_CHOICES, get_skill_path


_BUNDLED_SKILL = Path(__file__).parents[2] / "resources" / "claude_skill" / "SKILL.md"


@click.command()
@click.option(
    "--target",
    type=click.Choice(TARGET_CHOICES),
    default="claude",
    show_default=True,
    help="AI coding assistant to install the skill for.",
)
@click.option("--force", "-f", is_flag=True, help="Overwrite existing skill.")
@add_common_options()
def install_cmd(target: str, force: bool, **kwargs: Any) -> int:
    """Install the ggshield skill for an AI coding assistant."""
    dest = get_skill_path(target)

    if dest.exists() and not force:
        raise UnexpectedError(
            f"ggshield skill is already installed at {dest}. Use --force to overwrite."
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_BUNDLED_SKILL, dest)
    click.echo(
        f"ggshield skill installed at {click.style(str(dest), fg='yellow', bold=True)}"
    )
    return 0
