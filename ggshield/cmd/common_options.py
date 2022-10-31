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


def add_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        _verbose_option(cmd)
        return cmd

    return decorator
