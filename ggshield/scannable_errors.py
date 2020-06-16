from ast import literal_eval
from typing import Dict, List

import click
from pygitguardian.models import Detail

from .text_utils import STYLE, format_text, pluralize


def handle_scan_error(detail: Detail, chunk: List[Dict[str, str]]):
    if detail.status_code == 401:
        raise click.UsageError(detail.detail)

    click.echo(
        format_text("Error scanning. Results may be incomplete.", STYLE["error"]),
        err=True,
    )
    try:
        details = literal_eval(detail.detail)
        if isinstance(details, list) and details:
            click.echo(
                format_text(
                    f"Add the following {pluralize('file', len(details))}"
                    " to your paths-ignore:",
                    STYLE["error"],
                ),
                err=True,
            )
        for i, inner_detail in enumerate(details):
            if inner_detail:
                click.echo(
                    f"- {format_text(chunk[i]['filename'], STYLE['filename'])}:"
                    f" {str(inner_detail)}",
                    err=True,
                )
        return
    except Exception:
        click.echo(
            f"Error {str(detail)}", err=True,
        )
