import json
from functools import partial
from typing import Any, Callable, Iterable, Iterator, List, TextIO

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.core.config import Config
from ggshield.core.errors import handle_exception
from ggshield.core.text_utils import create_progress_bar, display_info
from ggshield.scan import ScanContext, ScanMode, Scannable, StringScannable
from ggshield.secret import SecretScanCollection, SecretScanner


def generate_files_from_docsets(
    file: TextIO, verbose: bool = False
) -> Iterator[Scannable]:
    for line in file:
        obj = json.loads(line)
        documents = obj["documents"]
        for document in documents:
            if verbose:
                display_info(f"  * {document['id']}")
            yield StringScannable(document["id"], document["content"])


def create_scans_from_docset_files(
    scanner: SecretScanner,
    input_files: Iterable[TextIO],
    progress_callback: Callable[..., None],
    verbose: bool = False,
) -> List[SecretScanCollection]:
    scans: List[SecretScanCollection] = []

    for input_file in input_files:
        if verbose:
            display_info(f"- {click.format_filename(input_file.name)}")

        files = generate_files_from_docsets(input_file, verbose)
        results = scanner.scan(files)
        scans.append(
            SecretScanCollection(id=input_file.name, type="docset", results=results)
        )
        progress_callback(advance=1)

    return scans


@click.command()
@click.argument("files", nargs=-1, type=click.File(), required=True)
@add_secret_scan_common_options()
@click.pass_context
def docset_cmd(
    ctx: click.Context,
    files: List[TextIO],
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    scan docset JSONL files.
    """
    config: Config = ctx.obj["config"]
    output_handler = create_output_handler(ctx)
    try:
        with create_progress_bar(doc_type="files") as progress:

            scan_context = ScanContext(
                scan_mode=ScanMode.DOCSET,
                command_path=ctx.command_path,
            )
            scanner = SecretScanner(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                ignored_matches=config.user_config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.user_config.secret.ignored_detectors,
            )
            task_scan = progress.add_task(
                "[green]Scanning content...", total=len(files)
            )
            scans = create_scans_from_docset_files(
                scanner=scanner,
                input_files=files,
                verbose=config.user_config.verbose,
                progress_callback=partial(progress.update, task_scan),
            )

        return output_handler.process_scan(
            SecretScanCollection(id=scan_context.command_id, type="docset", scans=scans)
        )
    except Exception as error:
        return handle_exception(error, config.user_config.verbose)
