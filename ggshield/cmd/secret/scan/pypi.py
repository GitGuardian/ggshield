import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, List, Pattern, Set, Tuple

import click
from packaging.requirements import InvalidRequirement
from unearth import Link, PackageFinder

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.secret.scan.ui_utils import print_file_list
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.core.scan import ScanContext, ScanMode, Scannable
from ggshield.core.scan.file import create_files_from_paths
from ggshield.core.scanner_ui import create_scanner_ui
from ggshield.utils.archive import safe_unpack
from ggshield.utils.files import ListFilesMode
from ggshield.verticals.secret import SecretScanCollection, SecretScanner


PYPI_DOWNLOAD_TIMEOUT = 30
DEFAULT_INDEX_URL = "https://pypi.org/simple/"


def _get_index_urls() -> List[str]:
    index_urls = [os.environ.get("PIP_INDEX_URL", DEFAULT_INDEX_URL)]
    extra_index_url = os.environ.get("PIP_EXTRA_INDEX_URL")
    if extra_index_url:
        index_urls.extend(extra_index_url.split())
    return index_urls


def _enforce_deadline(deadline: float) -> None:  # pragma: no cover
    """Give up once the PYPI_DOWNLOAD_TIMEOUT budget is spent."""
    if time.monotonic() > deadline:
        raise TimeoutError(f"timed out after {PYPI_DOWNLOAD_TIMEOUT}s")


def _download_link(
    finder: PackageFinder, link: Link, dest: Path, deadline: float
) -> None:
    """Stream the distribution at `link` into `dest`, giving up once `deadline`
    is reached."""
    with finder.session.get_stream(link.normalized) as response:
        response.raise_for_status()
        with dest.open("wb") as f:
            for chunk in response.iter_bytes():
                _enforce_deadline(deadline)
                f.write(chunk)


def save_package_to_tmp(temp_dir: Path, package_name: str) -> None:
    ui.display_heading("Downloading package")

    deadline = time.monotonic() + PYPI_DOWNLOAD_TIMEOUT

    finder = PackageFinder(
        index_urls=_get_index_urls(),
        ignore_compatibility=True,
    )

    try:
        best_match = finder.find_best_match(package_name).best
    except InvalidRequirement as exc:
        raise UnexpectedError(
            f'Invalid requirement with package name "{package_name}": {exc}'
        )
    except Exception as exc:
        raise UnexpectedError(f'Failed to look up "{package_name}": {exc}')

    if best_match is None:
        raise UnexpectedError(f'Could not find a package matching "{package_name}".')

    archive_path = temp_dir / best_match.link.filename
    try:
        _enforce_deadline(deadline)
        _download_link(
            finder=finder,
            link=best_match.link,
            dest=archive_path,
            deadline=deadline,
        )
    except Exception as exc:
        raise UnexpectedError(f'Failed to download "{package_name}": {exc}')


def get_files_from_package(
    archive_dir: Path,
    package_name: str,
    exclusion_regexes: Set[Pattern[str]],
) -> Tuple[List[Scannable], List[Path]]:
    archive: Path = next(archive_dir.iterdir())

    ui.display_heading("Unpacking package")
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

    Under the hood this command downloads the package from the index without
    installing or running it. Set the `PIP_INDEX_URL` (and optionally
    `PIP_EXTRA_INDEX_URL`) environment variable to download from a custom index
    instead of PyPI.
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config
    output_handler = create_output_handler(ctx)

    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        temp_path = Path(temp_dir)
        save_package_to_tmp(temp_dir=temp_path, package_name=package_name)

        files, binary_paths = get_files_from_package(
            archive_dir=temp_path,
            package_name=package_name,
            exclusion_regexes=ctx_obj.exclusion_regexes,
        )
        print_file_list(files, binary_paths)
        ui.display_heading("Starting scan")

        with create_scanner_ui(len(files)) as scanner_ui:
            scan_context = ScanContext(
                scan_mode=ScanMode.PYPI,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx_obj.client,
                cache=ctx_obj.cache,
                secret_config=config.user_config.secret,
                scan_context=scan_context,
            )
            results = scanner.scan(files, scanner_ui=scanner_ui)
        scan = SecretScanCollection(id=package_name, type="path_scan", results=results)

        return output_handler.process_scan(scan)
