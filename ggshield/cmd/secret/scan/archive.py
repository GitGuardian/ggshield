import shutil
import tempfile
from pathlib import Path
from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.errors import UnexpectedError
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.scan.file import get_files_from_paths
from ggshield.utils.click import RealPath
from ggshield.verticals.secret import SecretScanCollection, SecretScanner


@click.command()
@click.argument(
    "path", nargs=1, type=RealPath(exists=True, resolve_path=True), required=True
)
@add_secret_scan_common_options()
@click.pass_context
def archive_cmd(
    ctx: click.Context,
    path: Path,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan an archive file. Supported archive formats are zip, tar, tar.gz, tar.bz2 and tar.xz.
    """
    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        temp_path = Path(temp_dir)
        try:
            shutil.unpack_archive(path, extract_dir=temp_path)
        except Exception as exn:
            raise UnexpectedError(f'Failed to unpack "{path}" archive: {exn}')

        ctx_obj = ContextObj.get(ctx)
        config = ctx_obj.config
        verbose = config.user_config.verbose
        files = get_files_from_paths(
            paths=[temp_path],
            exclusion_regexes=ctx_obj.exclusion_regexes,
            recursive=True,
            yes=True,
            display_scanned_files=verbose,
            display_binary_files=verbose,
            ignore_git=True,
        )

        with ctx_obj.ui.create_scanner_ui(len(files), verbose=verbose) as ui:
            scan_context = ScanContext(
                scan_mode=ScanMode.ARCHIVE,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx_obj.client,
                cache=ctx_obj.cache,
                scan_context=scan_context,
                ignored_matches=config.user_config.secret.ignored_matches,
                ignored_detectors=config.user_config.secret.ignored_detectors,
            )
            results = scanner.scan(files, scanner_ui=ui)

        scan = SecretScanCollection(id=path, type="archive_scan", results=results)

        output_handler = create_output_handler(ctx)
        return output_handler.process_scan(scan)
