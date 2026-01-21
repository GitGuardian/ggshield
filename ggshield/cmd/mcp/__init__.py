from typing import Any

import click

from ggshield.cmd.mcp.discover import discover_cmd
from ggshield.cmd.utils.common_options import add_common_options


@click.group(commands={"discover": discover_cmd})
@add_common_options()
def mcp_group(**kwargs: Any) -> None:
    """Commands to work with MCP (Model Context Protocol) servers."""
