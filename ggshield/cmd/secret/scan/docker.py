import tempfile
from pathlib import Path

import click

from ggshield.core.utils import handle_exception
from ggshield.output import OutputHandler
from ggshield.scan.docker import docker_save_to_tmp, docker_scan_archive


# bailout if docker command takes longer than 6 minutes
DOCKER_COMMAND_TIMEOUT = 360


@click.command()
@click.option(
    "--docker-timeout",
    type=click.INT,
    default=DOCKER_COMMAND_TIMEOUT,
    help="Timeout for Docker commands.",
    metavar="SECONDS",
    show_default=True,
)
@click.argument("name", nargs=1, type=click.STRING, required=True)
@click.pass_context
def docker_name_cmd(ctx: click.Context, name: str, docker_timeout: int) -> int:
    """
    scan a docker image <NAME>.

    ggshield will try to pull the image if it's not available locally.
    """

    with tempfile.TemporaryDirectory(suffix="ggshield") as temporary_dir:
        config = ctx.obj["config"]
        output_handler: OutputHandler = ctx.obj["output_handler"]

        try:
            archive = Path(temporary_dir) / "archive.tar"
            docker_save_to_tmp(name, archive, docker_timeout)

            scan = docker_scan_archive(
                archive=archive,
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                verbose=config.verbose,
                matches_ignore=config.secret.ignored_matches,
                scan_id=name,
                ignored_detectors=config.secret.ignored_detectors,
            )

            return output_handler.process_scan(scan)
        except Exception as error:
            return handle_exception(error, config.verbose)
