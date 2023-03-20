from pathlib import Path
from typing import Any, Optional, Sequence, Type

import click
from pygitguardian import GGClient
from pygitguardian.iac_models import IaCScanParameters, IaCScanResult
from pygitguardian.models import Detail

from ggshield.cmd.common_options import add_common_options
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.text_utils import display_error
from ggshield.iac.filter import get_iac_files_from_paths
from ggshield.iac.policy_id import POLICY_ID_PATTERN, validate_policy_id
from ggshield.output import OutputHandler
from ggshield.output.json.iac_json_output_handler import IaCJSONOutputHandler
from ggshield.output.text.iac_text_output_handler import IaCTextOutputHandler
from ggshield.scan import ScanCollection, ScanContext, ScanMode


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
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
)
@add_common_options()
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    json: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan a directory for IaC vulnerabilities.
    """
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)
    result = iac_scan(ctx, directory)
    scan = ScanCollection(id=str(directory), type="path_scan", iac_result=result)

    output_handler_cls: Type[OutputHandler]
    if json:
        output_handler_cls = IaCJSONOutputHandler
    else:
        output_handler_cls = IaCTextOutputHandler
    config: Config = ctx.obj["config"]
    output_handler = output_handler_cls(
        show_secrets=False, verbose=config.user_config.verbose
    )
    return output_handler.process_scan(scan)


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


def iac_scan(ctx: click.Context, directory: Path) -> Optional[IaCScanResult]:
    files = get_iac_files_from_paths(
        path=directory,
        exclusion_regexes=ctx.obj["exclusion_regexes"],
        verbose=ctx.obj["config"].verbose,
        # If the repository is a git repository, ignore untracked files
        ignore_git=False,
    )

    config = ctx.obj["config"]
    client = ctx.obj["client"]

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = client.iac_directory_scan(
        directory,
        files.filenames,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.IAC_DIRECTORY,
        ).get_http_headers(),
    )

    if not scan.success or not isinstance(scan, IaCScanResult):
        handle_scan_error(client, scan)
        return None
    return scan


def handle_scan_error(client: GGClient, detail: Detail) -> None:
    if detail.status_code == 401:
        raise APIKeyCheckError(client.base_uri, "Invalid API key.")
    display_error("\nError scanning.")
    display_error(str(detail))
