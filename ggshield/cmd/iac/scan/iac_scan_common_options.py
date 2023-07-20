"""
This module defines options which should be available on all iac scan subcommands.

To use it:
- Add the `@add_common_iac_scan_options()` decorator after all the `click.option()`
    calls of the command function.
- Add a `**kwargs: Any` argument to the command function.

The `kwargs` argument is required because due to the way click works,
`add_common_options()` adds an argument for each option it defines.
"""
from pathlib import Path
from typing import Any, Callable, Sequence

import click

from ggshield.cmd.common_options import (
    add_common_options,
    exit_zero_option,
    json_option,
)
from ggshield.core.client import create_client_from_config
from ggshield.core.config.config import Config
from ggshield.core.filter import init_exclusion_regexes
from ggshield.iac.policy_id import POLICY_ID_PATTERN, validate_policy_id


AnyFunction = Callable[..., Any]

_minimum_severity_option = click.option(
    "--minimum-severity",
    "minimum_severity",
    type=click.Choice(("LOW", "MEDIUM", "HIGH", "CRITICAL")),
    help="Minimum severity of the policies.",
)


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

_ignore_path_option = click.option(
    "--ignore-path",
    "--ipa",
    "ignore_paths",
    default=None,
    type=click.Path(),
    multiple=True,
    help="""
    Do not scan paths that match the specified glob-like patterns.
    """,
)

all_option = click.option(
    "--all",
    is_flag=True,
    default=None,
    help="Raise all vulnerabilities in the final state.",
)

directory_argument = click.argument(
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
    # using a default value here makes the deprecated `iac scan` fail
)


def add_iac_scan_common_options() -> Callable[[AnyFunction], AnyFunction]:
    def decorator(cmd: AnyFunction) -> AnyFunction:
        add_common_options()(cmd)
        exit_zero_option(cmd)
        _minimum_severity_option(cmd)
        _ignore_policy_option(cmd)
        _ignore_path_option(cmd)
        json_option(cmd)
        return cmd

    return decorator


def update_context(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
) -> None:
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_client_from_config(config)

    if ignore_paths is not None:
        config.user_config.iac.ignored_paths.update(ignore_paths)

    ctx.obj["exclusion_regexes"] = init_exclusion_regexes(
        config.user_config.iac.ignored_paths
    )

    if ignore_policies is not None:
        config.user_config.iac.ignored_policies.update(ignore_policies)

    if exit_zero is not None:
        config.user_config.exit_zero = exit_zero

    if minimum_severity is not None:
        config.user_config.iac.minimum_severity = minimum_severity
