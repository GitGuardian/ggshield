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
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

import click

from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.debug_logs import setup_debug_logs
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


def create_ctx_callback(name: str) -> ClickCallback:
    """Helper function to define a Click option callback for simple cases where we only
    have to set a value on Click context object if the option is defined.
    """

    def callback(
        ctx: click.Context, param: click.Parameter, value: Optional[ArgT]
    ) -> Optional[ArgT]:
        if value is not None:
            setattr(ctx.obj, name, value)
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
    if value is not None:
        setup_debug_logs(filename=None)
    return value


# The --debug option is marked as "is_eager" so that we can setup logs as soon as
# possible. If we don't then log commands for the creation of the Config instance
# are ignored.
_debug_option = click.option(
    "--debug",
    is_flag=True,
    default=None,
    is_eager=True,
    help="Send log output to stderr. Equivalent to `--log-file -`.",
    callback=debug_callback,
)


def log_file_callback(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[str]:
    if value is not None:
        setup_debug_logs(filename=None if value == "-" else value)
    return value


# The --log-file option is marked as "is_eager" so that we can setup logs as soon as
# possible. If we don't then log commands for the creation of the Config instance
# are ignored.
_log_file_option = click.option(
    "--log-file",
    metavar="FILE",
    is_eager=True,
    help="Send log output to FILE. Use '-' to redirect to stderr.",
    envvar="GITGUARDIAN_LOG_FILE",
    callback=log_file_callback,
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


exit_zero_option = click.option(
    "--exit-zero",
    is_flag=True,
    default=None,
    envvar="GITGUARDIAN_EXIT_ZERO",
    help=(
        "Always return a 0 (non-error) status code, even if incidents are found."
        " This option can also be set with the `GITGUARDIAN_EXIT_ZERO` environment"
        " variable."
    ),
    callback=create_config_callback("exit_zero"),
)


minimum_severity_option = click.option(
    "--minimum-severity",
    "minimum_severity",
    type=click.Choice(("LOW", "MEDIUM", "HIGH", "CRITICAL")),
    help="Minimum severity of the policies.",
)

ignore_path_option = click.option(
    "--ignore-path",
    "--ipa",
    "ignore_paths",
    default=None,
    multiple=True,
    help="Do not scan paths that match the specified glob-like patterns.",
    metavar="PATTERN",
)


def add_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        _verbose_option(cmd)
        _debug_option(cmd)
        _log_file_option(cmd)
        _allow_self_signed_option(cmd)
        _check_for_updates(cmd)
        return cmd

    return decorator


json_option = click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=None,
    help="Use JSON output.",
    callback=create_ctx_callback("use_json"),
)


directory_argument = click.argument(
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
    # using a default value here makes the deprecated `iac scan` fail
)

all_option = click.option(
    "--all",
    "scan_all",
    is_flag=True,
    default=False,
    help="Reports all vulnerabilities in the final state.",
)

reference_option = click.option(
    "--ref",
    required=True,
    type=click.STRING,
    help="A Git reference, such as a commit ID, a reference relative to HEAD or a remote.",
    metavar="GIT_REF",
)
staged_option = click.option(
    "--staged",
    is_flag=True,
    help="Include staged changes in the scan.",
)
