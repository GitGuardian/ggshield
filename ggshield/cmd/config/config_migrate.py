from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.errors import UnexpectedError


@click.command()
@click.pass_context
@add_common_options()
def config_migrate_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Migrate configuration file to the latest version
    """
    config = ContextObj.get(ctx).config

    if not config._config_path.exists():
        raise UnexpectedError(
            f"No configuration file found at {config._config_path}.\n"
            "Run this command from the directory containing your configuration file, or point ggshield to it with"
            " `ggshield --config-path <path> config migrate`."
        )

    # Clear all deprecation messages, so that they do not show up when we quit
    config.user_config.deprecation_messages = []

    # First save to a new path, then rename the current config file to .old
    # and the new file to the current file. This way if something goes wrong
    # while saving, the existing file is left untouched.
    new_path = config._config_path.with_name(config._config_path.name + ".new")
    config.user_config.save(new_path)

    old_path = config._config_path.with_name(config._config_path.name + ".old")
    config._config_path.rename(old_path)

    new_path.rename(config._config_path)

    click.echo(
        f"Configuration file has been migrated. The previous version has been kept as a backup as {old_path}."
    )
    return 0
