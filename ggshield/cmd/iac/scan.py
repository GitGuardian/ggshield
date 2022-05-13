from pathlib import Path
from typing import Any, Sequence

import click

from ggshield.iac.utils import POLICY_ID_PATTERN, validate_policy_id


def validate_exclude(_ctx: Any, _param: Any, value: Sequence[str]) -> None:
    invalid_excluded_policies = [
        policy_id for policy_id in value if not validate_policy_id(policy_id)
    ]
    if len(invalid_excluded_policies) > 0:
        raise ValueError(
            f"The policies {invalid_excluded_policies} do not match the pattern '{POLICY_ID_PATTERN.pattern}'"
        )


@click.command()
@click.option(
    "--exit-zero",
    is_flag=True,
    help="Always return 0 (non-error) status code.",
)
@click.option(
    "--level",
    type=click.Choice(("LOW", "MEDIUM", "HIGH", "CRITICAL")),
    help="Level of the blocking alerts.",
    default="LOW",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose display mode.")
@click.option(
    "--ignore-policy",
    "--ipo",
    "ignore_policies",
    multiple=True,
    help="Policies to exclude from the results.",
    callback=validate_exclude,
)
@click.option(
    "--ignore-path",
    "--ipa",
    "ignore_paths",
    multiple=True,
    help="Do not scan the specified paths.",
)
@click.option("--json", is_flag=True, help="JSON output.")
@click.argument(
    "directory", type=click.Path(exists=True, readable=True, path_type=type(Path))
)
def scan_cmd(
    exit_zero: bool,
    level: str,
    verbose: bool,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    json: bool,
    directory: Path,
) -> None:
    pass
