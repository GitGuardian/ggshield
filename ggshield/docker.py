import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import click
from pygitguardian.client import GGClient

from ggshield.config import Cache
from ggshield.output import OutputHandler
from ggshield.scan import ScanCollection, get_files_from_docker_archive
from ggshield.utils import SupportedScanMode, handle_exception


# bailout if docker command takes longer than 6 minutes
DOCKER_COMMAND_TIMEOUT = 360


class DockerArchiveCreationError(Exception):
    pass


def docker_pull_image(image_name: str, timeout: int) -> None:
    """
    Pull docker image and raise exception on timeout or failed to find image

    Timeout after `timeout` seconds.
    """
    command = ["docker", "pull", image_name]
    try:
        subprocess.run(
            command,
            check=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError:
        raise click.ClickException(f'Image "{image_name}" not found')
    except subprocess.TimeoutExpired:
        raise click.ClickException('Command "{}" timed out'.format(" ".join(command)))


def docker_save_to_tmp(image_name: str, destination_path: Path, timeout: int) -> None:
    """
    Do a `docker save <image_name> -o <destination_path>`

    Limit docker commands to run at most `timeout` seconds.
    """
    command = ["docker", "save", image_name, "-o", str(destination_path)]

    try:
        click.echo("Saving docker image... ", nl=False)
        subprocess.run(
            command,
            check=True,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        click.echo("OK")
    except subprocess.CalledProcessError as exc:
        err_string = str(exc.stderr)
        if "No such image" in err_string or "reference does not exist" in err_string:
            click.echo("need to download image first")
            docker_pull_image(image_name, timeout)

            docker_save_to_tmp(image_name, destination_path, timeout)
        raise click.ClickException(
            f"Unable to save docker archive:\nError: {err_string}"
        )
    except subprocess.TimeoutExpired:
        raise click.ClickException('Command "{}" timed out'.format(" ".join(command)))


def docker_scan_archive(
    archive: Path,
    client: GGClient,
    cache: Cache,
    verbose: bool,
    matches_ignore: Iterable[str],
    all_policies: bool,
    scan_id: str,
    banlisted_detectors: Optional[Set[str]] = None,
) -> ScanCollection:
    files = get_files_from_docker_archive(archive)
    with click.progressbar(length=len(files.files), label="Scanning") as progressbar:

        def update_progress(chunk: List[Dict[str, Any]]) -> None:
            progressbar.update(len(chunk))

        results = files.scan(
            client=client,
            cache=cache,
            matches_ignore=matches_ignore,
            all_policies=all_policies,
            verbose=verbose,
            mode_header=SupportedScanMode.DOCKER.value,
            on_file_chunk_scanned=update_progress,
            banlisted_detectors=banlisted_detectors,
        )

    return ScanCollection(id=scan_id, type="scan_docker_archive", results=results)


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
                matches_ignore=config.matches_ignore,
                all_policies=config.all_policies,
                scan_id=name,
                banlisted_detectors=config.banlisted_detectors,
            )

            return output_handler.process_scan(scan)
        except Exception as error:
            return handle_exception(error, config.verbose)


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

    Hidden command `ggshield scan docker-archive`
    """
    config = ctx.obj["config"]
    output_handler: OutputHandler = ctx.obj["output_handler"]

    try:
        scan = docker_scan_archive(
            archive=archive,
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            verbose=config.verbose,
            matches_ignore=config.matches_ignore,
            all_policies=config.all_policies,
            scan_id=str(archive),
            banlisted_detectors=config.banlisted_detectors,
        )

        return output_handler.process_scan(scan)
    except Exception as error:
        return handle_exception(error, config.verbose)
