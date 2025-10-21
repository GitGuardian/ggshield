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

from typing import Any, Callable, List, Optional, TypeVar

import click

from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.debug import setup_debug_mode
from ggshield.cmd.utils.output_format import OutputFormat
from ggshield.core import ui
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
    return ContextObj.get(ctx).config.user_config


def create_ctx_callback(*option_names: str) -> ClickCallback[ArgT]:
    """Helper function to define a Click option callback for simple cases where we only
    have to set a value on Click context object if the option is defined.
    """

    def callback(
        ctx: click.Context, param: click.Parameter, value: Optional[ArgT]
    ) -> Optional[ArgT]:
        if value is not None and ctx.obj is not None:
            obj = ContextObj.get(ctx)
            for name in option_names[:-1]:
                obj = getattr(obj, name)
            setattr(obj, option_names[-1], value)
        return value

    return callback


def create_config_callback(*option_names: str) -> ClickCallback[ArgT]:
    """Helper function to define a Click option callback for simple cases where we only
    have to set a configuration attribute if the option is defined.

    to reach UserConfig.foo, set option_names to ["foo"]
    to reach Userconfig.secret.bar, set option_names to ["secret", "bar"]
    """

    def callback(
        ctx: click.Context, param: click.Parameter, value: Optional[ArgT]
    ) -> Optional[ArgT]:
        if value is not None and ctx.obj is not None:
            # If ctx.obj has not been defined yet, then it means we are in the top-level
            # cli() function and the config has not been loaded yet, so we can't change
            # it.
            #
            # cli() takes care of applying the few config-related options it receives
            # itself.
            obj = get_config_from_context(ctx)
            for name in option_names[:-1]:
                obj = getattr(obj, name)
            setattr(obj, option_names[-1], value)
        return value

    return callback


def verbose_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[bool]
) -> Optional[bool]:
    if value is not None:
        ui.ensure_level(ui.Level.VERBOSE)
    return value


_verbose_option = click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=None,
    help="Verbose display mode.",
    callback=verbose_callback,
)


def debug_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[bool]
) -> Optional[bool]:
    if value is not None:
        setup_debug_mode()
    return value


_debug_option = click.option(
    "--debug",
    is_flag=True,
    default=None,
    help="Send log output to stderr. Equivalent to `--log-file -`.",
    callback=debug_callback,
)


def log_file_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[str]:
    if value is not None:
        setup_debug_mode(filename=value)
    return value


_log_file_option = click.option(
    "--log-file",
    metavar="FILE",
    help="Send log output to FILE. Use '-' to redirect to stderr.",
    envvar="GITGUARDIAN_LOG_FILE",
    callback=log_file_callback,
)


def allow_self_signed_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[bool]
) -> Optional[bool]:
    if value:
        ui.display_warning(
            "The --allow-self-signed option is deprecated. Use --insecure instead."
        )
    return create_config_callback("insecure")(ctx, param, value)


_allow_self_signed_option = click.option(
    "--allow-self-signed",
    is_flag=True,
    default=None,
    help="Deprecated: use --insecure.",
    callback=allow_self_signed_callback,
)

_insecure_option = click.option(
    "--insecure",
    is_flag=True,
    default=None,
    help="Skip all certificate verification checks. WARNING: this option makes the transfer insecure.",
    callback=create_config_callback("insecure"),
)

_check_for_updates = click.option(
    "--check-for-updates/--no-check-for-updates",
    is_flag=True,
    default=None,
    help="After executing commands, check if a new version of ggshield is available.",
    callback=create_ctx_callback("check_for_updates"),
)


exit_zero_option = click.option(
    "--exit-zero",
    is_flag=True,
    default=None,
    envvar="GITGUARDIAN_EXIT_ZERO",
    help=(
        "Return a 0 (non-error) status code, even if incidents are found."
        " An error status code will still be returned for other errors, such as connection errors."
        " This option can also be set with the `GITGUARDIAN_EXIT_ZERO` environment"
        " variable."
    ),
    callback=create_config_callback("exit_zero"),
)


def add_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        _verbose_option(cmd)
        _debug_option(cmd)
        _log_file_option(cmd)
        _allow_self_signed_option(cmd)
        _insecure_option(cmd)
        _check_for_updates(cmd)
        return cmd

    return decorator


def _set_json_output_format(
    ctx: click.Context, param: click.Parameter, value: Optional[bool]
) -> Optional[bool]:
    if value:
        ctx_obj = ContextObj.get(ctx)
        ctx_obj.output_format = OutputFormat.JSON
    return value


json_option = click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=None,
    help="Shorthand for `--format json`.",
    callback=_set_json_output_format,
)


def _set_output_format(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[str]:
    if value:
        ctx_obj = ContextObj.get(ctx)
        ctx_obj.output_format = OutputFormat(value)
    return value


def _create_format_option(
    formats: List[OutputFormat],
) -> Callable[[click.decorators.FC], click.decorators.FC]:
    return click.option(
        "--format",
        type=click.Choice([x.value for x in formats]),
        help="Format to use for the output.",
        callback=_set_output_format,
    )


# If a command only supports text and json formats, it should use this option
text_json_format_option = _create_format_option([OutputFormat.TEXT, OutputFormat.JSON])


# If a command supports text, sarif and json formats, it should use this option
text_json_sarif_format_option = _create_format_option(
    [OutputFormat.TEXT, OutputFormat.JSON, OutputFormat.SARIF]
)


instance_option = click.option(
    "--instance",
    required=False,
    type=str,
    help="URL of the instance to use.",
    metavar="URL",
    callback=create_ctx_callback("config", "cmdline_instance_name"),
)
