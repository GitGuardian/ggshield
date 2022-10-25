from typing import Dict

from ggshield import __version__
from ggshield.core.utils import ScanContext, ScanMode


def get_headers(scan_context: ScanContext) -> Dict[str, str]:
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

    if scan_context.extra_headers:
        headers = {**headers, **scan_context.extra_headers}

    return {
        **{f"GGShield-{key}": str(value) for key, value in headers.items()},
        "mode": scan_context.scan_mode.value
        if isinstance(scan_context.scan_mode, ScanMode)
        else scan_context.scan_mode,
    }
