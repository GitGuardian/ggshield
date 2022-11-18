"""
This module defines options which should be available on all commands, such as the
-v, --verbose option.

To use it:
- Add the `@add_common_options()` decorator after all the `click.option()` calls of the
  command function.
- Add a `**kwargs: Any` argument to the command function.

The `kwargs` argument is required because due to the way click works,
`add_common_options()` adds an argument for each option it defines.
"""
from typing import Any, Callable, Optional, cast

import click

from ggshield.cmd.debug_logs import setup_debug_logs
from ggshield.core.config.user_config import UserConfig


AnyFunction = Callable[..., Any]


def _get_config(ctx: click.Context) -> UserConfig:
    return cast(UserConfig, ctx.obj["config"].user_config)


def _verbose_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[bool]
) -> Optional[bool]:
    if value is not None:
        _get_config(ctx).verbose = value
    return value


_verbose_option = click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=None,
    help="Verbose display mode.",
    callback=_verbose_callback,
)


def debug_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[bool]
) -> Optional[bool]:
    # The --debug option is marked as "is_eager" so that we can setup logs as soon as
    # possible. If we don't then log commands for the creation of the Config instance
    # are ignored
    if value is not None:
        setup_debug_logs(value is True)
    return value


_debug_option = click.option(
    "--debug",
    is_flag=True,
    default=None,
    is_eager=True,
    help="Show debug information.",
    callback=debug_callback,
)


def allow_self_signed_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[bool]
) -> Optional[bool]:
    if value is not None:
        _get_config(ctx).allow_self_signed = value
    return value


_allow_self_signed_option = click.option(
    "--allow-self-signed",
    is_flag=True,
    default=None,
    help="Ignore ssl verification.",
    callback=allow_self_signed_callback,
)


def add_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        _verbose_option(cmd)
        _debug_option(cmd)
        _allow_self_signed_option(cmd)
        return cmd

    return decorator
