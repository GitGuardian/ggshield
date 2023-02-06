import shutil
import tempfile
from functools import partial
from pathlib import Path
from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.core.config import Config
from ggshield.core.errors import UnexpectedError
from ggshield.core.file_utils import get_files_from_paths
from ggshield.core.text_utils import create_progress_bar
from ggshield.scan import Files, ScanCollection, ScanContext, ScanMode, SecretScanner


@click.command()
@click.argument(
    "path", nargs=1, type=click.Path(exists=True, resolve_path=True), required=True
)
@add_secret_scan_common_options()
@click.pass_context
def archive_cmd(
    ctx: click.Context,
    path: str,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    scan archive <PATH>.
    """
    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        try:
            shutil.unpack_archive(path, extract_dir=Path(temp_dir))
        except Exception as exn:
            raise UnexpectedError(f'Failed to unpack "{path}" archive: {exn}')

        config: Config = ctx.obj["config"]
        files: Files = get_files_from_paths(
            paths=[temp_dir],
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            recursive=True,
            yes=True,
            verbose=config.verbose,
            ignore_git=True,
        )

        with create_progress_bar(doc_type="files") as progress:

            scan_context = ScanContext(
                scan_mode=ScanMode.ARCHIVE,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                scan_context=scan_context,
                ignored_matches=config.secret.ignored_matches,
                ignored_detectors=config.secret.ignored_detectors,
                ignore_known_secrets=config.ignore_known_secrets,
            )
            task_scan = progress.add_task(
                "[green]Scanning Archive...", total=len(files.files)
            )
            results = scanner.scan(
                files.files,
                progress_callback=partial(progress.update, task_scan),
            )

        scan = ScanCollection(id=path, type="archive_scan", results=results)

        output_handler = create_output_handler(ctx)
        return output_handler.process_scan(scan)
