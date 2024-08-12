import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Pattern, Set, Tuple

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.secret.scan.ui_utils import print_file_list
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.errors import UnexpectedError
from ggshield.core.scan import ScanContext, ScanMode, Scannable
from ggshield.core.scan.file import create_files_from_paths
from ggshield.core.text_utils import display_heading
from ggshield.utils.archive import safe_unpack
from ggshield.utils.files import ListFilesMode
from ggshield.verticals.secret import SecretScanCollection, SecretScanner


PYPI_DOWNLOAD_TIMEOUT = 30


def save_package_to_tmp(temp_dir: Path, package_name: str) -> None:
    command: List[str] = [
        "pip",
        "download",
        package_name,
        "--dest",
        str(temp_dir),
        "--no-deps",
    ]

    try:
        display_heading("Downloading package")
        subprocess.run(
            command,
            check=True,
            stdout=sys.stderr,
            stderr=sys.stderr,
            timeout=PYPI_DOWNLOAD_TIMEOUT,
        )

    except subprocess.CalledProcessError:
        raise UnexpectedError(f'Failed to download "{package_name}"')

    except subprocess.TimeoutExpired:
        raise UnexpectedError('Command "{}" timed out'.format(" ".join(command)))


def get_files_from_package(
    archive_dir: Path,
    package_name: str,
    exclusion_regexes: Set[Pattern[str]],
) -> Tuple[List[Scannable], List[Path]]:
    archive: Path = next(archive_dir.iterdir())

    display_heading("Unpacking package")
    try:
        safe_unpack(archive, extract_dir=archive_dir)
    except Exception as exn:
        raise UnexpectedError(f'Failed to unpack package "{package_name}": {exn}.')

    exclusion_regexes.add(re.compile(re.escape(archive.name)))

    return create_files_from_paths(
        paths=[archive_dir],
        exclusion_regexes=exclusion_regexes,
        list_files_mode=ListFilesMode.ALL,
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
    Scan a pypi package.

    Under the hood this command uses the `pip download` command to download the python
    package.

    You can use pip environment variables or configuration files to set `pip download`
    parameters as explained in [pip documentation][1].  For example, you can set pip
    `--index-url` parameter with the `PIP_INDEX_URL` environment variable.

    [1]: https://pip.pypa.io/en/stable/topics/configuration/
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    output_handler = create_output_handler(ctx)
    verbose = config.user_config.verbose

    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        temp_path = Path(temp_dir)
        save_package_to_tmp(temp_dir=temp_path, package_name=package_name)

        files, binary_paths = get_files_from_package(
            archive_dir=temp_path,
            package_name=package_name,
            exclusion_regexes=ctx_obj.exclusion_regexes,
        )
        if verbose:
            print_file_list(files, binary_paths)
        display_heading("Starting scan")

        with ctx_obj.ui.create_scanner_ui(len(files), verbose=verbose) as ui:
            scan_context = ScanContext(
                scan_mode=ScanMode.PYPI,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx_obj.client,
                cache=ctx_obj.cache,
                ignored_matches=config.user_config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.user_config.secret.ignored_detectors,
            )
            results = scanner.scan(files, scanner_ui=ui)
        scan = SecretScanCollection(id=package_name, type="path_scan", results=results)

        return output_handler.process_scan(scan)
