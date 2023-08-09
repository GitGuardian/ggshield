from typing import Any

import click

from ggshield.cmd.common_options import add_common_options
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.text_utils import pluralize


@click.command()
@click.option(
    "--last-found",
    is_flag=True,
    help="Ignore secrets found in the last ggshield secret scan run.",
)
@add_common_options()
@click.pass_context
def ignore_cmd(
    ctx: click.Context,
    last_found: bool,
    **kwargs: Any,
) -> None:
    """
    Ignore some secrets.
    """
    if last_found:
        config: Config = ctx.obj["config"]
        cache = ctx.obj["cache"]
        nb = ignore_last_found(config, cache)
        path = config.config_path
        secrets_word = pluralize("secret", nb)
        click.echo(
            f"Added {nb} {secrets_word} to the `secret.ignored-matches` section of {path}."
        )


def ignore_last_found(config: Config, cache: Cache) -> int:
    """
    Add last found secrets from .cache_ggshield into ignored_matches
    in the local .gitguardian.yaml config file so that they are ignored on next run
    Secrets are added as `hash`
    """
    for secret in cache.last_found_secrets:
        config.add_ignored_match(secret)
    config.save()
    return len(cache.last_found_secrets)
