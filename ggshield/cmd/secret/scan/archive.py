import shutil
import sys
import tempfile
from pathlib import Path
from typing import List

import click

from ggshield.core.config import Config
from ggshield.core.file_utils import get_files_from_paths
from ggshield.core.utils import ScanContext, ScanMode
from ggshield.output import OutputHandler
from ggshield.scan import File, Files, ScanCollection


@click.command()
@click.argument(
    "path", nargs=1, type=click.Path(exists=True, resolve_path=True), required=True
)
@click.pass_context
def archive_cmd(ctx: click.Context, path: str) -> int:  # pragma: no cover
    """
    scan archive <PATH>.
    """
    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        try:
            shutil.unpack_archive(path, extract_dir=Path(temp_dir))
        except Exception as exn:
            raise click.ClickException(f'Failed to unpack "{path}" archive: {exn}')

        config: Config = ctx.obj["config"]
        files: Files = get_files_from_paths(
            paths=[temp_dir],
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            recursive=True,
            yes=True,
            verbose=config.verbose,
            ignore_git=True,
        )

        with click.progressbar(
            length=len(files.files), label="Scanning", file=sys.stderr
        ) as progressbar:

            def update_progress(chunk: List[File]) -> None:
                progressbar.update(len(chunk))

            scan_context = ScanContext(
                scan_mode=ScanMode.ARCHIVE,
                command_path=ctx.command_path,
            )

            results = files.scan(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                scan_context=scan_context,
                matches_ignore=config.secret.ignored_matches,
                ignored_detectors=config.secret.ignored_detectors,
                on_file_chunk_scanned=update_progress,
            )

            scan = ScanCollection(id=path, type="archive_scan", results=results)

            output_handler: OutputHandler = ctx.obj["output_handler"]
            return output_handler.process_scan(scan)
