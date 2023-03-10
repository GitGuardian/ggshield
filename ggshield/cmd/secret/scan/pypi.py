import re
import shutil
import subprocess
import sys
import tempfile
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Set

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.core.config import Config
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import UnexpectedError
from ggshield.core.file_utils import get_files_from_paths
from ggshield.core.text_utils import create_progress_bar
from ggshield.scan import Files, ScanCollection, ScanContext, ScanMode, SecretScanner


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
        raise UnexpectedError(f'Failed to download "{package_name}"')

    except subprocess.TimeoutExpired:
        raise UnexpectedError('Command "{}" timed out'.format(" ".join(command)))


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
        raise UnexpectedError(f'Failed to unpack package "{package_name}": {exn}.')

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
@add_secret_scan_common_options()
@click.pass_context
def pypi_cmd(
    ctx: click.Context,
    package_name: str,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    scan a pypi package <NAME>.
    """
    config: Config = ctx.obj["config"]
    output_handler = create_output_handler(ctx)

    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        save_package_to_tmp(temp_dir=temp_dir, package_name=package_name)

        files: Files = get_files_from_package(
            archive_dir=temp_dir,
            package_name=package_name,
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            verbose=config.verbose,
        )

        with create_progress_bar(doc_type="files") as progress:

            scan_context = ScanContext(
                scan_mode=ScanMode.PYPI,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                ignored_matches=config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.secret.ignored_detectors,
                ignore_known_secrets=config.ignore_known_secrets,
            )
            task_scan = progress.add_task(
                "[green]Scanning PyPI Package...", total=len(files.files)
            )
            results = scanner.scan(
                files.files,
                progress_callback=partial(progress.update, task_scan),
                scan_threads=MAX_WORKERS,
            )
        scan = ScanCollection(id=package_name, type="path_scan", results=results)

        return output_handler.process_scan(scan)
