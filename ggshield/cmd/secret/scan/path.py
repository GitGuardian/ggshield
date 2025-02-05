from pathlib import Path
from typing import Any, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.secret.scan.ui_utils import print_file_list
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.files import check_directory_not_ignored
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import ScanContext, ScanMode, Scannable
from ggshield.core.scan.file import create_files_from_paths
from ggshield.core.scanner_ui import create_scanner_ui
from ggshield.utils.click import RealPath
from ggshield.utils.files import ListFilesMode
from ggshield.verticals.secret import SecretScanCollection, SecretScanner


@click.command()
@click.argument("paths", nargs=-1, type=RealPath(exists=True), required=True)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively.")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan.")
@click.option(
    "--use-gitignore", is_flag=True, help="Honor content of .gitignore files."
)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def path_cmd(
    ctx: click.Context,
    paths: List[Path],
    recursive: bool,
    yes: bool,
    use_gitignore: bool,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan files and directories.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    ctx_obj.client = create_client_from_config(config)
    output_handler = create_output_handler(ctx)

    for path in paths:
        check_directory_not_ignored(path, ctx_obj.exclusion_regexes)

    if not recursive:
        if path := next((x for x in paths if x.is_dir()), None):
            raise click.UsageError(
                f"{click.format_filename(path)} is a directory."
                " Use --recursive to scan directories."
            )

    files, binary_paths = create_files_from_paths(
        paths=paths,
        exclusion_regexes=ctx_obj.exclusion_regexes,
        list_files_mode=(
            ListFilesMode.ALL_BUT_GITIGNORED if use_gitignore else ListFilesMode.ALL
        ),
    )
    print_file_list(files, binary_paths)
    if not yes:
        confirm_scan(files)

    if ui.is_verbose():
        ui.display_heading("Starting scan")
    target = paths[0] if len(paths) == 1 else Path.cwd()
    target_path = target if target.is_dir() else target.parent
    with create_scanner_ui(len(files)) as scanner_ui:
        scan_context = ScanContext(
            scan_mode=ScanMode.PATH,
            command_path=ctx.command_path,
            target_path=target_path,
        )

        scanner = SecretScanner(
            client=ctx_obj.client,
            cache=ctx_obj.cache,
            scan_context=scan_context,
            secret_config=config.user_config.secret,
        )
        results = scanner.scan(files, scanner_ui=scanner_ui)
    scan = SecretScanCollection(
        id=" ".join(str(x) for x in paths), type="path_scan", results=results
    )

    return output_handler.process_scan(scan)


def confirm_scan(files: List[Scannable]) -> None:
    count = len(files)
    if count > 1:
        click.confirm(
            f"{count} files will be scanned. Do you want to continue?",
            abort=True,
            err=True,
        )
