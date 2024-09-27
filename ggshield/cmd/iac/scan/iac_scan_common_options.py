"""
This module defines options which should be available on all iac scan subcommands.

To use it:
- Add the `@add_common_iac_scan_options()` decorator after all the `click.option()`
    calls of the command function.
- Add a `**kwargs: Any` argument to the command function.

The `kwargs` argument is required due to the way click works,
`add_common_options()` adds an argument for each option it defines.
"""

from typing import Any, Callable, Sequence

import click

from ggshield.cmd.utils.common_options import (
    AnyFunction,
    add_common_options,
    exit_zero_option,
    ignore_path_option,
    json_option,
    minimum_severity_option_iac,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.config.user_config import (
    POLICY_ID_PATTERN,
    IaCConfigIgnoredPath,
    IaCConfigIgnoredPolicy,
    validate_policy_id,
)
from ggshield.core.filter import init_exclusion_regexes


def _validate_exclude(_ctx: Any, _param: Any, value: Sequence[str]) -> Sequence[str]:
    invalid_excluded_policies = [
        policy_id for policy_id in value if not validate_policy_id(policy_id)
    ]
    if len(invalid_excluded_policies) > 0:
        raise ValueError(
            f"The policies {invalid_excluded_policies} do not match the pattern '{POLICY_ID_PATTERN.pattern}'"
        )
    return value


_ignore_policy_option = click.option(
    "--ignore-policy",
    "--ipo",
    "ignore_policies",
    multiple=True,
    help="Policies to exclude from the results.",
    callback=_validate_exclude,
)


def add_iac_scan_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        add_common_options()(cmd)
        exit_zero_option(cmd)
        minimum_severity_option_iac(cmd)
        _ignore_policy_option(cmd)
        ignore_path_option(cmd)
        json_option(cmd)
        text_json_format_option(cmd)
        return cmd

    return decorator


def update_context(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
) -> None:
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    ctx_obj.client = create_client_from_config(config)

    if ignore_paths is not None:
        config.user_config.iac.ignored_paths.extend(
            (IaCConfigIgnoredPath(path=path) for path in ignore_paths)
        )

    ctx_obj.exclusion_regexes = init_exclusion_regexes(
        {ignored.path for ignored in config.user_config.iac.ignored_paths}
    )

    if ignore_policies is not None:
        config.user_config.iac.ignored_policies.extend(
            (IaCConfigIgnoredPolicy(policy=policy) for policy in ignore_policies)
        )

    if exit_zero is not None:
        config.user_config.exit_zero = exit_zero

    if minimum_severity is not None:
        config.user_config.iac.minimum_severity = minimum_severity
