import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import click

from ggshield.core.config import Config
from ggshield.core.file_utils import get_files_from_paths
from ggshield.core.utils import SupportedScanMode
from ggshield.output import OutputHandler
from ggshield.scan import Files, ScanCollection


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

            def update_progress(chunk: List[Dict[str, Any]]) -> None:
                progressbar.update(len(chunk))

            results = files.scan(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                matches_ignore=config.secret.ignored_matches,
                mode_header=SupportedScanMode.ARCHIVE.value,
                ignored_detectors=config.secret.ignored_detectors,
                on_file_chunk_scanned=update_progress,
            )

            scan = ScanCollection(id=path, type="archive_scan", results=results)

            output_handler: OutputHandler = ctx.obj["output_handler"]
            return output_handler.process_scan(scan)
