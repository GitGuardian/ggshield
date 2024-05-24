from collections import defaultdict
from pathlib import Path
from typing import Any, Dict

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.filter import censor_string
from ggshield.verticals.secret.fix.list import Location, list_locations
from ggshield.verticals.secret.fix.remediate import OPENAI_API_KEY, remediate


@click.command()
@add_secret_scan_common_options()
@click.pass_context
def fix(
    ctx: click.Context,
    **_: Any,
) -> int:
    """Commands to help remediate secrets"""
    if OPENAI_API_KEY is None:
        raise click.ClickException("OPENAI_API_KEY environment variable must be set")

    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config, ctx_obj.ui)

    locations = list_locations(ctx_obj.client)
    locations_by_file: Dict[Path, list[Location]] = defaultdict(list)
    for location in locations:
        filepath = Path(location.filepath)
        locations_by_file[filepath].append(location)

    click.echo()
    for filepath, locations in locations_by_file.items():
        click.echo(f"- {filepath}")
        for location in locations:
            status = (
                click.style("⨯ ", fg="red") + censor_string(location.string_matched)
                if location.need_remediation
                else click.style("✓", fg="green")
            )
            click.echo(f"  - {location.detector_name} {status}")

        locations_to_remediate = [
            location for location in locations if location.need_remediation
        ]
        if len(locations_to_remediate) > 0 and click.confirm(
            "Remediate?", default=True
        ):
            remediate(filepath, locations_to_remediate)
            click.echo()

    return 0
