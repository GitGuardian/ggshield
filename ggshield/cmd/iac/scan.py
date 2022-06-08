from pathlib import Path
from typing import Any, Optional, Sequence, Type

import click

from ggshield import __version__
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.extra_headers import get_extra_headers
from ggshield.core.filter import init_exclusion_regexes
from ggshield.iac.filter import get_iac_files_from_paths
from ggshield.iac.models import IaCScanResult
from ggshield.iac.models.iac_scan_parameters import IaCScanParameters
from ggshield.iac.utils import POLICY_ID_PATTERN, create_tar, validate_policy_id
from ggshield.output import OutputHandler
from ggshield.output.json.iac_json_output_handler import IaCJSONOutputHandler
from ggshield.output.text.iac_text_output_handler import IaCTextOutputHandler
from ggshield.scan import ScanCollection
from ggshield.scan.scannable_errors import handle_scan_error


def validate_exclude(_ctx: Any, _param: Any, value: Sequence[str]) -> Sequence[str]:
    invalid_excluded_policies = [
        policy_id for policy_id in value if not validate_policy_id(policy_id)
    ]
    if len(invalid_excluded_policies) > 0:
        raise ValueError(
            f"The policies {invalid_excluded_policies} do not match the pattern '{POLICY_ID_PATTERN.pattern}'"
        )
    return value


@click.command()
@click.option(
    "--exit-zero",
    is_flag=True,
    help="Always return 0 (non-error) status code.",
)
@click.option(
    "--minimum-severity",
    "minimum_severity",
    type=click.Choice(("LOW", "MEDIUM", "HIGH", "CRITICAL")),
    help="Minimum severity of the policies",
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
    default=None,
    type=click.Path(),
    multiple=True,
    help="Do not scan the specified paths.",
)
@click.option("--json", is_flag=True, help="JSON output.")
@click.argument(
    "directory", type=click.Path(exists=True, readable=True, path_type=Path)
)
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    verbose: bool,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    json: bool,
    directory: Path,
) -> int:
    update_context(
        ctx, exit_zero, minimum_severity, verbose, ignore_policies, ignore_paths, json
    )
    result = iac_scan(ctx, directory)
    scan = ScanCollection(id=str(directory), type="path_scan", iac_result=result)

    output_handler: OutputHandler = ctx.obj["output_handler"]
    return output_handler.process_scan(scan)


def update_context(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    verbose: bool,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    json: bool,
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

    if verbose is not None:
        config.user_config.verbose = verbose

    if exit_zero is not None:
        config.user_config.exit_zero = exit_zero

    if minimum_severity is not None:
        config.user_config.iac.minimum_severity = minimum_severity

    output_handler_cls: Type[OutputHandler] = IaCTextOutputHandler
    if json:
        output_handler_cls = IaCJSONOutputHandler

    ctx.obj["output_handler"] = output_handler_cls(
        show_secrets=False, verbose=config.user_config.verbose
    )


def iac_scan(ctx: click.Context, directory: Path) -> Optional[IaCScanResult]:
    files = get_iac_files_from_paths(
        path=directory,
        exclusion_regexes=ctx.obj["exclusion_regexes"],
        verbose=ctx.obj["config"].verbose,
        ignore_git=True,
    )
    tar = create_tar(directory, files)

    config = ctx.obj["config"]
    client = ctx.obj["client"]

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = client.directory_scan(
        tar,
        scan_parameters,
        {
            "GGShield-Version": __version__,
            "GGShield-Command-Path": ctx.command_path
            if ctx is not None
            else "external",
            **get_extra_headers(ctx),
        },
    )

    if not scan.success or not isinstance(scan, IaCScanResult):
        handle_scan_error(scan, files.scannable_list)
        return None
    return scan
