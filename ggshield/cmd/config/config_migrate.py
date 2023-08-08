import os
from typing import Any

import click

from ggshield.cmd.common_options import add_common_options
from ggshield.core.config import Config


@click.command()
@click.pass_context
@add_common_options()
def config_migrate_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Migrate configuration file to the latest version
    """
    config: Config = ctx.obj["config"]

    # Clear all deprecation messages, so that they do not show up when we quit
    config.user_config.deprecation_messages = []

    # First save to a new path, then rename the current config file to .old
    # and the new file to the current file. This way if something goes wrong
    # while saving, the existing file is left untouched.
    new_path = config._config_path + ".new"
    config.user_config.save(new_path)

    old_path = config._config_path + ".old"
    os.rename(config._config_path, old_path)
    os.rename(new_path, config._config_path)

    click.echo(
        f"Configuration file has been migrated. The previous version has been kept as a backup as {old_path}."
    )
    return 0
