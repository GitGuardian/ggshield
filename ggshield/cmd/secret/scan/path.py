from typing import List

import click

from ggshield.core.constants import MAX_WORKERS
from ggshield.core.file_utils import get_files_from_paths
from ggshield.core.utils import ScanContext, ScanMode, handle_exception
from ggshield.output import OutputHandler
from ggshield.scan import ScanCollection


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

        scan_context = ScanContext(
            scan_mode=ScanMode.PATH,
            command_path=ctx.command_path,
        )

        results = files.scan(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            matches_ignore=config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.secret.ignored_detectors,
            scan_threads=MAX_WORKERS,
        )
        scan = ScanCollection(id=" ".join(paths), type="path_scan", results=results)

        return output_handler.process_scan(scan)
    except Exception as error:
        return handle_exception(error, config.verbose)
