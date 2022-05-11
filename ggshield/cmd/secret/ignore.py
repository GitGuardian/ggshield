import click

from ggshield.core.cache import Cache
from ggshield.core.config import Config


@click.command()
@click.option(
    "--last-found",
    is_flag=True,
    help="Ignore secrets found in the last ggshield secret scan run",
)
@click.pass_context
def ignore_cmd(ctx: click.Context, last_found: bool) -> None:
    """
    Ignore some secrets.
    """

    ignore_cmd_impl(ctx, last_found)


@click.command(hidden=True)
@click.option(
    "--last-found",
    is_flag=True,
    help="Ignore secrets found in the last ggshield secret scan run",
)
@click.pass_context
def deprecated_ignore_cmd(ctx: click.Context, last_found: bool) -> None:
    """
    Deprecated: use `ggshield secret ignore (...)` instead.
    """

    ignore_cmd_impl(ctx, last_found)


def ignore_cmd_impl(ctx: click.Context, last_found: bool) -> None:
    if last_found:
        config = ctx.obj["config"]
        cache = ctx.obj["cache"]
        nb = ignore_last_found(config, cache)
        click.echo(
            f"{nb} secrets have been added to your ignore list in"
            " .gitguardian.yaml under matches-ignore section."
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
