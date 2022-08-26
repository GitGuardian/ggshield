import uuid
from typing import Dict, Optional

import click

from ggshield import __version__


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


def get_extra_headers(
    ctx: Optional[click.Context], command_id: Optional[str] = None
) -> Dict[str, str]:
    """
    Returns the extra headers to send in HTTP requests.
    If `command_id` is not None, a `GGShield-Command-Id` header will be sent.
    Adds the "GGShield-" prefix to the header's names.
    """

    command_path = ctx.command_path if ctx is not None else "external"

    headers = {
        "Version": __version__,
        "Command-Path": command_path,
    }
    if command_id:
        headers["Command-Id"] = command_id

    if ctx is not None and isinstance(ctx.obj, dict):
        context_headers = ctx.obj.get("headers")
        if context_headers:
            headers = {**headers, **context_headers}

    return {f"GGShield-{key}": str(value) for key, value in headers.items()}


def generate_command_id() -> str:
    """
    Returns an opaque ID used to identify multiple API calls belonging to the same command
    """
    return str(uuid.uuid4())
