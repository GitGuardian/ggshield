from pathlib import Path
from typing import Any, Optional

import click
from pygitguardian.client import _create_tar

from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError, UnexpectedError
from ggshield.core.text_utils import display_error, display_info, display_warning
from ggshield.sca.client import SCAClient
from ggshield.sca.file_selection import get_sca_scan_all_filepaths
from ggshield.sca.sca_scan_models import SCAScanAllOutput, SCAScanParameters
from ggshield.scan import ScanContext, ScanMode


def display_sca_beta_warning(func):
    """
    Displays warning about SCA commands being in beta.
    """

    def func_with_beta_warning(*args, **kwargs):
        display_warning(
            "This feature is still in beta, its behavior may change in future versions."
        )
        return func(*args, **kwargs)

    return func_with_beta_warning


@click.group()
@click.pass_context
def scan_group(*args, **kwargs: Any) -> None:
    """Perform a SCA scan."""


@scan_group.command(name="diff")
@click.argument(
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
)
@click.option(
    "--ref",
    metavar="REF",
    help="Git reference to compare working directory to.",
)
@click.option(
    "--staged",
    is_flag=True,
    help="Compare staged state instead of working state.",
)
@click.pass_context
@display_sca_beta_warning
def scan_diff_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    ref: str,
    **kwargs: Any,
) -> int:
    """
    Find SCA vulnerabilities in a git working directory, compared to git history.
    """
    return 0


@scan_group.command(name="all")
@click.argument(
    "directory",
    type=click.Path(exists=True, readable=True, path_type=Path, file_okay=False),
    required=False,
)
@click.pass_context
@display_sca_beta_warning
def scan_all_cmd(
    ctx: click.Context,
    directory: Optional[Path],
    **kwargs: Any,
) -> SCAScanAllOutput:
    """
    Scan a directory for SCA vulnerabilities.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx)

    result = sca_scan_all(ctx, directory)

    # TODO, should be handled by an output_handler in the future
    return result


def update_context(ctx: click.Context) -> None:
    """
    Basic implementation, should be populated with required parameters later.
    """
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_client_from_config(config)

    # Empty for now
    ctx.obj["exclusion_regexes"] = set()


def sca_scan_all(ctx: click.Context, directory: Path) -> SCAScanAllOutput:
    """
    Scan an entire directory for SCA Vulnerabilities.

    - List SCA related files with a first call to SCA compute files API
    - Create a tar archive with the required files contents
    - Launches the scan with a call to SCA public API
    """
    client = SCAClient(ctx.obj["client"])

    sca_filepaths = get_sca_scan_all_filepaths(
        directory=directory,
        exclusion_regexes=ctx.obj["exclusion_regexes"],
        verbose=ctx.obj["config"].verbose,
        client=client,
    )

    if len(sca_filepaths) == 0:
        display_info("No file to scan.")
        # Not an error, return an empty SCAScanAllOutput
        return SCAScanAllOutput()

    # empty for now
    scan_parameters = SCAScanParameters()

    tar = _create_tar(directory, sca_filepaths)

    # Call to full scan API and get results
    scan_result = client.sca_scan_directory(
        tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.SCA_DIRECTORY,
        ).get_http_headers(),
    )

    if not isinstance(scan_result, SCAScanAllOutput):
        if scan_result.status_code == 401:
            raise APIKeyCheckError(client.base_uri, "Invalid API key.")
        display_error("Error scanning.")
        display_error(str(scan_result))
        raise UnexpectedError("Unexpected error while performing SCA scan all.")

    return scan_result
