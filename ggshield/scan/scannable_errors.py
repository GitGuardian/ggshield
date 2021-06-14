from ast import literal_eval
from typing import Dict, List

import click
from pygitguardian.models import Detail

from ggshield.text_utils import STYLE, display_error, format_text, pluralize


def handle_scan_error(detail: Detail, chunk: List[Dict[str, str]]) -> None:
    if detail.status_code == 401:
        raise click.UsageError(detail.detail)

    details = None

    display_error("\nError scanning. Results may be incomplete.")
    try:
        # try to load as list of dicts to get per file details
        details = literal_eval(detail.detail)
    except Exception:
        pass

    if isinstance(details, list) and details:
        # if the details had per file details
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
    else:
        # if the details had a request error
        filenames = ", ".join([file_dict["filename"] for file_dict in chunk])
        display_error(
            "The following chunk is affected:\n"
            f"{format_text(filenames, STYLE['filename'])}"
        )

        display_error(str(detail))
