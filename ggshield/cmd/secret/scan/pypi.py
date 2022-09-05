import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Set

import click

from ggshield.core.config import Config
from ggshield.core.file_utils import get_files_from_paths
from ggshield.core.utils import ScanContext, ScanMode
from ggshield.output import OutputHandler
from ggshield.scan import File, Files, ScanCollection


PYPI_DOWNLOAD_TIMEOUT = 30


def save_package_to_tmp(temp_dir: str, package_name: str) -> None:
    command: List[str] = [
        "pip",
        "download",
        package_name,
        "--dest",
        temp_dir,
        "--no-deps",
    ]

    try:
        click.echo("Downloading pip package... ", nl=False, err=True)
        subprocess.run(
            command,
            check=True,
            stdout=sys.stderr,
            stderr=sys.stderr,
            timeout=PYPI_DOWNLOAD_TIMEOUT,
        )
        click.echo("OK", err=True)

    except subprocess.CalledProcessError:
        raise click.ClickException(f'Failed to download "{package_name}"')

    except subprocess.TimeoutExpired:
        raise click.ClickException('Command "{}" timed out'.format(" ".join(command)))


def get_files_from_package(
    archive_dir: str,
    package_name: str,
    exclusion_regexes: Set[re.Pattern],
    verbose: bool,
) -> Files:
    archive_dir_path = Path(archive_dir)
    archive: Path = next(archive_dir_path.iterdir())
    unpack_kwargs: Dict[str, str] = (
        {"format": "zip"} if archive.suffix == ".whl" else {}
    )

    try:
        shutil.unpack_archive(
            str(archive), extract_dir=archive_dir_path, **unpack_kwargs
        )
    except Exception as exn:
        raise click.ClickException(f'Failed to unpack package "{package_name}": {exn}.')

    exclusion_regexes.add(re.compile(re.escape(archive.name)))

    return get_files_from_paths(
        paths=[archive_dir],
        exclusion_regexes=exclusion_regexes,
        recursive=True,
        yes=True,
        verbose=verbose,
        ignore_git=True,
    )


@click.command()
@click.argument("package_name", nargs=1, type=click.STRING, required=True)
@click.pass_context
def pypi_cmd(ctx: click.Context, package_name: str) -> int:  # pragma: no cover
    """
    scan a pypi package <NAME>.
    """
    config: Config = ctx.obj["config"]
    output_handler: OutputHandler = ctx.obj["output_handler"]

    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        save_package_to_tmp(temp_dir=temp_dir, package_name=package_name)

        files: Files = get_files_from_package(
            archive_dir=temp_dir,
            package_name=package_name,
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            verbose=config.verbose,
        )

        with click.progressbar(
            length=len(files.files), label="Scanning", file=sys.stderr
        ) as progressbar:

            def update_progress(chunk: List[File]) -> None:
                progressbar.update(len(chunk))

            scan_context = ScanContext(
                scan_mode=ScanMode.PYPI,
                command_path=ctx.command_path,
            )

            results = files.scan(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                matches_ignore=config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.secret.ignored_detectors,
                on_file_chunk_scanned=update_progress,
            )
        scan = ScanCollection(id=package_name, type="path_scan", results=results)

        return output_handler.process_scan(scan)
