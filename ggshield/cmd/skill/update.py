import shutil
from pathlib import Path
from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options

from .targets import TARGET_CHOICES, get_skill_path


_BUNDLED_SKILL = Path(__file__).parents[2] / "resources" / "claude_skill" / "SKILL.md"


@click.command()
@click.option(
    "--target",
    type=click.Choice(TARGET_CHOICES),
    default="claude",
    show_default=True,
    help="AI coding assistant to update the skill for.",
)
@add_common_options()
def update_cmd(target: str, **kwargs: Any) -> int:
    """Update the installed ggshield skill."""
    dest = get_skill_path(target)
    fresh = not dest.exists()

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_BUNDLED_SKILL, dest)

    if fresh:
        click.echo(
            f"ggshield skill installed at {click.style(str(dest), fg='yellow', bold=True)}"
        )
    else:
        click.echo(
            f"ggshield skill updated at {click.style(str(dest), fg='yellow', bold=True)}"
        )
    return 0
