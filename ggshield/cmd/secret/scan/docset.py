import json
from typing import Any, Iterable, Iterator, List, TextIO

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import ScanContext, ScanMode, Scannable, StringScannable
from ggshield.core.scanner_ui import create_message_only_scanner_ui
from ggshield.core.ui.ggshield_ui import GGShieldProgress
from ggshield.verticals.secret import SecretScanCollection, SecretScanner


def generate_files_from_docsets(file: TextIO) -> Iterator[Scannable]:
    for line in file:
        obj = json.loads(line)
        documents = obj["documents"]
        for document in documents:
            ui.display_verbose(f"  * {document['id']}")
            yield StringScannable(document["id"], document["content"])


def create_scans_from_docset_files(
    scanner: SecretScanner, input_files: Iterable[TextIO], progress: GGShieldProgress
) -> List[SecretScanCollection]:
    scans: List[SecretScanCollection] = []

    for input_file in input_files:
        ui.display_verbose(f"- {click.format_filename(input_file.name)}")

        files = generate_files_from_docsets(input_file)
        with create_message_only_scanner_ui() as scanner_ui:
            results = scanner.scan(files, scanner_ui=scanner_ui)
        scans.append(
            SecretScanCollection(id=input_file.name, type="docset", results=results)
        )
        progress.advance(1)

    return scans


@click.command()
@click.argument("files", nargs=-1, type=click.File(), required=True)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def docset_cmd(
    ctx: click.Context,
    files: List[TextIO],
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan docset JSONL files.

    The JSONL files must be formatted using the ["Docset" format][1].

    \b
    [1]: https://docs.gitguardian.com/ggshield-docs/integrations/other-data-sources/other-data-sources
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config
    output_handler = create_output_handler(ctx)
    with ui.create_progress(len(files)) as progress:

        scan_context = ScanContext(
            scan_mode=ScanMode.DOCSET,
            command_path=ctx.command_path,
        )
        scanner = SecretScanner(
            client=ctx_obj.client,
            cache=ctx_obj.cache,
            secret_config=config.user_config.secret,
            scan_context=scan_context,
        )
        scans = create_scans_from_docset_files(
            scanner=scanner, input_files=files, progress=progress
        )

    return output_handler.process_scan(
        SecretScanCollection(id=scan_context.command_id, type="docset", scans=scans)
    )
