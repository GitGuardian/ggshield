"""
MCP Discover command - Discovers MCP servers and optionally probes them
for tools, resources, and prompts.
"""

import json
from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.verticals.ai.discovery import print_summary, run_discovery


@click.command(name="discover")
@click.option(
    "--json",
    "use_json",
    is_flag=True,
    default=False,
    help="Output as JSON",
)
@click.option(
    "--history",
    "scan_history",
    is_flag=True,
    default=False,
    help="Also backfill historical MCP tool calls parsed from agent transcripts.",
)
@add_common_options()
@click.pass_context
def discover_cmd(
    ctx: click.Context,
    use_json: bool,
    scan_history: bool,
    **kwargs: Any,
) -> None:
    """
    Discover MCP servers and their configuration.

    Parses configuration files from supported assistants.

    Examples:
      ggshield ai discover
      ggshield ai discover --json
      ggshield ai discover --history
    """
    config = ContextObj.get(ctx).config
    summary = run_discovery(config, scan_history=scan_history)
    if summary is None:
        return

    if use_json:
        click.echo(json.dumps(summary, indent=2))
    else:
        print_summary(summary)
