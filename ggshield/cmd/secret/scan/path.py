from functools import partial
from typing import List

import click

from ggshield.core.constants import MAX_WORKERS
from ggshield.core.file_utils import get_files_from_paths
from ggshield.core.text_utils import create_progress_bar
from ggshield.core.utils import handle_exception
from ggshield.output import OutputHandler
from ggshield.scan import ScanCollection, ScanContext, ScanMode, SecretScanner


@click.command()
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, resolve_path=True), required=True
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan")
@click.pass_context
def path_cmd(
    ctx: click.Context, paths: List[str], recursive: bool, yes: bool
) -> int:  # pragma: no cover
    """
    scan files and directories.
    """
    config = ctx.obj["config"]
    output_handler: OutputHandler = ctx.obj["output_handler"]
    try:
        files = get_files_from_paths(
            paths=paths,
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            recursive=recursive,
            yes=yes,
            verbose=config.verbose,
            # when scanning a path explicitly we should not care if it is a git repository or not
            ignore_git=True,
        )

        with create_progress_bar(doc_type="files") as progress:
            task_scan = progress.add_task(
                "[green]Scanning Path...", total=len(files.files)
            )

            scan_context = ScanContext(
                scan_mode=ScanMode.PATH,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                ignored_matches=config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.secret.ignored_detectors,
            )
            results = scanner.scan(
                files.files,
                progress_callback=partial(progress.update, task_scan),
                scan_threads=MAX_WORKERS,
            )
        scan = ScanCollection(id=" ".join(paths), type="path_scan", results=results)

        return output_handler.process_scan(scan)
    except Exception as error:
        return handle_exception(error, config.verbose)
