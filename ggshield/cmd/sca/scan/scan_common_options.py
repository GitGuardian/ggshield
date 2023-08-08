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

from ggshield.cmd.common_options import (
    AnyFunction,
    add_common_options,
    exit_zero_option,
    ignore_path_option,
    minimum_severity_option,
)
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.filter import init_exclusion_regexes


def add_sca_scan_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        add_common_options()(cmd)
        exit_zero_option(cmd)
        minimum_severity_option(cmd)
        ignore_path_option(cmd)
        return cmd

    return decorator


def update_context(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
) -> None:
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_client_from_config(config)

    if ignore_paths is not None:
        config.user_config.sca.ignored_paths.update(ignore_paths)

    ctx.obj["exclusion_regexes"] = init_exclusion_regexes(
        config.user_config.sca.ignored_paths
    )

    if exit_zero is not None:
        config.user_config.exit_zero = exit_zero

    if minimum_severity is not None:
        config.user_config.sca.minimum_severity = minimum_severity
