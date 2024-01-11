from pathlib import Path
from typing import Any, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.files import check_directory_not_ignored
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.scan.file import get_files_from_paths
from ggshield.utils.click import RealPath
from ggshield.verticals.secret import SecretScanCollection, SecretScanner


@click.command()
@click.argument(
    "paths", nargs=-1, type=RealPath(exists=True, resolve_path=True), required=True
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively.")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan.")
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def path_cmd(
    ctx: click.Context,
    paths: List[Path],
    recursive: bool,
    yes: bool,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan files and directories.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    output_handler = create_output_handler(ctx)
    verbose = config.user_config.verbose

    for path in paths:
        check_directory_not_ignored(path, ctx_obj.exclusion_regexes)

    files = get_files_from_paths(
        paths=paths,
        exclusion_regexes=ctx_obj.exclusion_regexes,
        recursive=recursive,
        yes=yes,
        display_scanned_files=verbose,
        display_binary_files=verbose,
        # when scanning a path explicitly we should not care if it is a git repository or not
        ignore_git=True,
    )

    target = paths[0] if len(paths) == 1 else Path.cwd()
    target_path = target if target.is_dir() else target.parent
    with ctx_obj.ui.create_scanner_ui(len(files), verbose=verbose) as scanner_ui:
        scan_context = ScanContext(
            scan_mode=ScanMode.PATH,
            command_path=ctx.command_path,
            target_path=target_path,
        )

        scanner = SecretScanner(
            client=ctx_obj.client,
            cache=ctx_obj.cache,
            ignored_matches=config.user_config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.user_config.secret.ignored_detectors,
        )
        results = scanner.scan(files, scanner_ui=scanner_ui)
    scan = SecretScanCollection(
        id=" ".join(str(x) for x in paths), type="path_scan", results=results
    )

    return output_handler.process_scan(scan)
