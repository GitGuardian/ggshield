from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options

from .targets import TARGET_CHOICES, get_skill_path


@click.command()
@click.option(
    "--target",
    type=click.Choice(TARGET_CHOICES),
    default="claude",
    show_default=True,
    help="AI coding assistant to uninstall the skill from.",
)
@add_common_options()
def uninstall_cmd(target: str, **kwargs: Any) -> int:
    """Uninstall the ggshield skill."""
    dest = get_skill_path(target)

    if not dest.exists():
        click.echo("ggshield skill is not installed.")
        return 0

    dest.unlink()

    # Remove parent dir if empty
    try:
        dest.parent.rmdir()
    except OSError:
        pass

    click.echo(
        f"ggshield skill uninstalled from {click.style(str(dest), fg='yellow', bold=True)}"
    )
    return 0
