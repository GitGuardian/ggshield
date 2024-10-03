"""
This module defines options which should be available on all sca scan subcommands.

To use it:
- Add the `@add_common_sca_scan_options()` decorator after all the `click.option()`
    calls of the command function.
- Add a `**kwargs: Any` argument to the command function.

The `kwargs` argument is required due to the way click works,
`add_common_options()` adds an argument for each option it defines.
"""

from typing import Callable, Sequence

import click
from click import UsageError

from ggshield.cmd.utils.common_options import (
    AnyFunction,
    add_common_options,
    exit_zero_option,
    ignore_path_option,
    json_option,
    minimum_severity_option_sca,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.filter import init_exclusion_regexes


ignore_fixable = click.option(
    "--ignore-fixable",
    is_flag=True,
    default=False,
    help="Ignore incidents related to vulnerabilities that have a fix.",
)


ignore_not_fixable = click.option(
    "--ignore-not-fixable",
    is_flag=True,
    default=False,
    help="Ignore incidents that cannot be fixed for now.",
)


def add_sca_scan_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        add_common_options()(cmd)
        exit_zero_option(cmd)
        minimum_severity_option_sca(cmd)
        ignore_path_option(cmd)
        json_option(cmd)
        text_json_format_option(cmd)
        ignore_fixable(cmd)
        ignore_not_fixable(cmd)
        return cmd

    return decorator


def update_context(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ignore_fixable: bool,
    ignore_not_fixable: bool,
) -> None:
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    ctx_obj.client = create_client_from_config(config)

    if ignore_paths is not None:
        config.user_config.sca.ignored_paths.update(ignore_paths)

    ctx_obj.exclusion_regexes = init_exclusion_regexes(
        config.user_config.sca.ignored_paths
    )

    if exit_zero is not None:
        config.user_config.exit_zero = exit_zero

    if minimum_severity is not None:
        config.user_config.sca.minimum_severity = minimum_severity

    if ignore_not_fixable and ignore_fixable:
        raise UsageError(
            "Cannot use simultaneously --ignore-not-fixable and --ignore-fixable flags."
        )

    if ignore_fixable:
        config.user_config.sca.ignore_fixable = ignore_fixable

    if ignore_not_fixable:
        config.user_config.sca.ignore_not_fixable = ignore_not_fixable
