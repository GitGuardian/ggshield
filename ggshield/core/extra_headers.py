from typing import Dict, Optional

import click

from ggshield import __version__
from ggshield.core.utils import ScanContext, ScanMode


def add_extra_header(ctx: Optional[click.Context], key: str, value: str) -> None:
    """
    Stores an extra header in the command's context.
    Existing headers cannot be overwritten.
    """
    if ctx is None:
        return

    if not isinstance(ctx.obj, dict):
        ctx.obj = {"headers": {}}
    if "headers" not in ctx.obj:
        ctx.obj["headers"] = {}

    if key not in ctx.obj["headers"]:
        ctx.obj["headers"][key] = value


def get_headers(
    scan_context: ScanContext, context_headers: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Returns the extra headers to send in HTTP requests.
    If `command_id` is not None, a `GGShield-Command-Id` header will be sent.
    Adds the "GGShield-" prefix to the header's names.
    """

    headers = {
        "Version": __version__,
        "Command-Path": scan_context.command_path,
        "Command-Id": scan_context.command_id,
    }

    if context_headers:
        headers = {**headers, **context_headers}

    return {
        **{f"GGShield-{key}": str(value) for key, value in headers.items()},
        "mode": scan_context.scan_mode.value
        if isinstance(scan_context.scan_mode, ScanMode)
        else scan_context.scan_mode,
    }
