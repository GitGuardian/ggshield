from typing import Callable, List, Optional

import click

from ggshield.cmd.common_options import (
    AnyFunction,
    add_common_options,
    create_config_callback,
    create_ctx_callback,
    exit_zero_option,
    get_config_from_context,
    json_option,
    use_json,
)
from ggshield.core.config import Config
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.utils import IGNORED_DEFAULT_WILDCARDS
from ggshield.secret.output import (
    SecretJSONOutputHandler,
    SecretOutputHandler,
    SecretTextOutputHandler,
)


def _get_secret_config(ctx: click.Context) -> SecretConfig:
    return get_config_from_context(ctx).secret


_output_option = click.option(
    "--output",
    "-o",
    type=click.Path(exists=False, resolve_path=True),
    default=None,
    help="Route ggshield output to file.",
    callback=create_ctx_callback("output"),
)


_show_secrets_option = click.option(
    "--show-secrets",
    is_flag=True,
    default=None,
    help="Show secrets in plaintext instead of hiding them.",
    callback=create_config_callback("secret", "show_secrets"),
)


def _exclude_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[List[str]]
) -> Optional[List[str]]:
    ignored_paths = _get_secret_config(ctx).ignored_paths
    if value is not None:
        ignored_paths.update(value)

    ignored_paths.update(IGNORED_DEFAULT_WILDCARDS)
    ctx.obj["exclusion_regexes"] = init_exclusion_regexes(ignored_paths)
    return value


_exclude_option = click.option(
    "--exclude",
    default=None,
    type=click.Path(),
    help="""
    Do not scan paths that match the specified glob-like patterns.
    """,
    multiple=True,
    callback=_exclude_callback,
)


_ignore_known_secrets_option = click.option(
    "--ignore-known-secrets",
    is_flag=True,
    default=None,
    help="Ignore secrets already known by GitGuardian dashboard.",
    callback=create_config_callback("secret", "ignore_known_secrets"),
)


def _banlist_detectors_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[List[str]]
) -> Optional[List[str]]:
    if value is not None:
        config = _get_secret_config(ctx)
        config.ignored_detectors.update(value)

    return value


_banlist_detectors_option = click.option(
    "--banlist-detector",
    "-b",
    default=None,
    help="Exclude results from a detector.",
    multiple=True,
    callback=_banlist_detectors_callback,
)


def add_secret_scan_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        add_common_options()(cmd)
        json_option(cmd)
        _output_option(cmd)
        _show_secrets_option(cmd)
        exit_zero_option(cmd)
        _exclude_option(cmd)
        _ignore_known_secrets_option(cmd)
        _banlist_detectors_option(cmd)
        return cmd

    return decorator


def create_output_handler(ctx: click.Context) -> SecretOutputHandler:
    """Read objects defined in ctx.obj and create the appropriate OutputHandler
    instance"""
    output_handler_cls = (
        SecretJSONOutputHandler if use_json(ctx) else SecretTextOutputHandler
    )
    config: Config = ctx.obj["config"]
    output = ctx.obj.get("output")
    return output_handler_cls(
        show_secrets=config.user_config.secret.show_secrets,
        verbose=config.user_config.verbose,
        output=output,
        ignore_known_secrets=config.user_config.secret.ignore_known_secrets,
    )
