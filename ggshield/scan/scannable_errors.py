from ast import literal_eval
from typing import Dict, List

import click
from pygitguardian.models import Detail

from ggshield.text_utils import STYLE, display_error, format_text, pluralize


def handle_scan_error(detail: Detail, chunk: List[Dict[str, str]]) -> None:
    if detail.status_code == 401:
        raise click.UsageError(detail.detail)

    display_error("Error scanning. Results may be incomplete.")
    try:
        details = literal_eval(detail.detail)
        if isinstance(details, list) and details:
            display_error(
                f"Add the following {pluralize('file', len(details))}"
                " to your paths-ignore:"
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
        click.echo(f"Error {str(detail)}", err=True)
