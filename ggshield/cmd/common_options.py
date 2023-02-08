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
from typing import Any, Callable, Optional, TypeVar, cast

import click

from ggshield.cmd.debug_logs import setup_debug_logs
from ggshield.core.config.user_config import UserConfig


AnyFunction = Callable[..., Any]


# The argument of a Click option callback function
ArgT = TypeVar("ArgT")

# A Click option callback function
ClickCallback = Callable[
    [click.Context, click.Parameter, Optional[ArgT]], Optional[ArgT]
]


def get_config_from_context(ctx: click.Context) -> UserConfig:
    """Returns the UserConfig object stored in Click context"""
    return cast(UserConfig, ctx.obj["config"].user_config)


def create_ctx_callback(name: str) -> ClickCallback:
    """Helper function to define a Click option callback for simple cases where we only
    have to set a value on Click context object if the option is defined.
    """

    def callback(
        ctx: click.Context, param: click.Parameter, value: Optional[ArgT]
    ) -> Optional[ArgT]:
        if value is not None:
            ctx.obj[name] = value
        return value

    return callback


def create_config_callback(*option_names: str) -> ClickCallback:
    """Helper function to define a Click option callback for simple cases where we only
    have to set a configuration attribute if the option is defined.

    to reach UserConfig.foo, set option_names to ["foo"]
    to reach Userconfig.secret.bar, set option_names to ["secret", "bar"]
    """

    def callback(
        ctx: click.Context, param: click.Parameter, value: Optional[ArgT]
    ) -> Optional[ArgT]:
        if value is not None:
            obj = get_config_from_context(ctx)
            for name in option_names[:-1]:
                obj = getattr(obj, name)
            setattr(obj, option_names[-1], value)
        return value

    return callback


_verbose_option = click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=None,
    help="Verbose display mode.",
    callback=create_config_callback("verbose"),
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


_allow_self_signed_option = click.option(
    "--allow-self-signed",
    is_flag=True,
    default=None,
    help="Ignore ssl verification.",
    callback=create_config_callback("allow_self_signed"),
)

_check_for_updates = click.option(
    "--check-for-updates/--no-check-for-updates",
    is_flag=True,
    default=None,
    help="After executing commands, check if a new version of ggshield is available.",
    callback=create_ctx_callback("check_for_updates"),
)


def add_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        _verbose_option(cmd)
        _debug_option(cmd)
        _allow_self_signed_option(cmd)
        _check_for_updates(cmd)
        return cmd

    return decorator
