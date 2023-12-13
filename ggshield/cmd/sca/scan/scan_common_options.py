"""
This module defines options which should be available on all sca scan subcommands.

To use it:
- Add the `@add_common_sca_scan_options()` decorator after all the `click.option()`
    calls of the command function.
- Add a `**kwargs: Any` argument to the command function.

The `kwargs` argument is required due to the way click works,
`add_common_options()` adds an argument for each option it defines.
"""
from pathlib import Path
from typing import Callable, Optional, Sequence

import click

from ggshield.cmd.utils.common_options import (
    AnyFunction,
    add_common_options,
    exit_zero_option,
    ignore_path_option,
    json_option,
    minimum_severity_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.filter import get_ignore_paths_from_sources, init_exclusion_regexes


def add_sca_scan_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        add_common_options()(cmd)
        exit_zero_option(cmd)
        minimum_severity_option(cmd)
        ignore_path_option(cmd)
        json_option(cmd)
        return cmd

    return decorator


def update_context(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    directory: Optional[Path] = None,
) -> None:
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    ctx_obj.client = create_client_from_config(config, ctx_obj.ui)

    exclusion_ignore_paths = get_ignore_paths_from_sources(
        cli_ignore_paths=ignore_paths or (),
        config_ignore_paths=config.user_config.sca.ignored_paths,
        config_path=config._config_path,
        directory=directory,
    )

    ctx_obj.exclusion_regexes = init_exclusion_regexes(exclusion_ignore_paths)

    if exit_zero is not None:
        config.user_config.exit_zero = exit_zero

    if minimum_severity is not None:
        config.user_config.sca.minimum_severity = minimum_severity
