import os

import click


@click.command()
@click.pass_context
def config_migrate_cmd(ctx: click.Context) -> None:
    """
    Migrate configuration file to the latest version
    """
    config = ctx.obj["config"]

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
