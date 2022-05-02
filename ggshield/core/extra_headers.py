from typing import Dict, Optional

import click


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


def get_extra_headers(ctx: Optional[click.Context]) -> Dict[str, str]:
    """
    Returns the extra headers stored in the command's context.
    Adds the prefix "GGShield-" to the header's names.
    """
    if (
        ctx is not None
        and isinstance(ctx.obj, dict)
        and isinstance(ctx.obj.get("headers"), dict)
    ):
        return {
            str(key): f"GGShield-{value}" for key, value in ctx.obj["headers"].items()
        }
    return {}
