from pathlib import Path

import click

from ggshield.core.utils import ScanContext, ScanMode, handle_exception
from ggshield.output import OutputHandler
from ggshield.scan.docker import docker_scan_archive


@click.command(hidden=True)
@click.argument(
    "archive", nargs=1, type=click.Path(exists=True, resolve_path=True), required=True
)
@click.pass_context
def docker_archive_cmd(
    ctx: click.Context,
    archive: Path,
) -> int:  # pragma: no cover
    """
    scan a docker archive <ARCHIVE> without attempting to save or pull the image.

    Hidden command `ggshield secret scan docker-archive`
    """
    config = ctx.obj["config"]
    output_handler: OutputHandler = ctx.obj["output_handler"]

    scan_context = ScanContext(
        scan_mode=ScanMode.DOCKER,
        command_path=ctx.command_path,
    )

    try:
        scan = docker_scan_archive(
            archive=archive,
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            matches_ignore=config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.secret.ignored_detectors,
        )

        return output_handler.process_scan(scan)
    except Exception as error:
        return handle_exception(error, config.verbose)
