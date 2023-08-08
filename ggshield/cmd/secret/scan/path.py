from typing import Any, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.core.config import Config
from ggshield.core.errors import handle_exception
from ggshield.scan import ScanContext, ScanMode
from ggshield.scan.file import get_files_from_paths
from ggshield.secret import RichSecretScannerUI, SecretScanCollection, SecretScanner


@click.command()
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, resolve_path=True), required=True
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively.")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan.")
@add_secret_scan_common_options()
@click.pass_context
def path_cmd(
    ctx: click.Context,
    paths: List[str],
    recursive: bool,
    yes: bool,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    scan files and directories.
    """
    config: Config = ctx.obj["config"]
    output_handler = create_output_handler(ctx)
    try:
        files = get_files_from_paths(
            paths=paths,
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            recursive=recursive,
            yes=yes,
            verbose=config.user_config.verbose,
            # when scanning a path explicitly we should not care if it is a git repository or not
            ignore_git=True,
        )

        with RichSecretScannerUI(len(files.files), dataset_type="Path") as ui:
            scan_context = ScanContext(
                scan_mode=ScanMode.PATH,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                ignored_matches=config.user_config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.user_config.secret.ignored_detectors,
            )
            results = scanner.scan(files.files, scanner_ui=ui)
        scan = SecretScanCollection(
            id=" ".join(paths), type="path_scan", results=results
        )

        return output_handler.process_scan(scan)
    except Exception as error:
        return handle_exception(error, config.user_config.verbose)
