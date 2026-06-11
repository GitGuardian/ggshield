import sys
from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.verticals.ai.hooks import AIHookScanner, emit_fail_open_response
from ggshield.verticals.secret import SecretScanner


MAX_READ_SIZE = 1024 * 1024 * 10  # We restrict stdin read to 10MB


@click.command()
@add_secret_scan_common_options()
@click.pass_context
def ai_hook_cmd(
    ctx: click.Context,
    **kwargs: Any,
) -> int:
    """
    Scan AI tool interactions for secrets.

    Reads a hook event from stdin as JSON, processes it,
    and outputs a response to stdout as JSON that blocks the action
    if secrets are detected.

    To install the hook for your AI coding tool, run:

    `ggshield install -t <your-code-assistant> -m [local|global]`
    """
    ctx_obj = ContextObj.get(ctx)

    # Read input from stdin
    stdin_content = sys.stdin.read(MAX_READ_SIZE).strip()

    try:
        config = ctx_obj.config
        ctx_obj.client = create_client_from_config(config)
        scanner = SecretScanner(
            client=ctx_obj.client,
            cache=ctx_obj.cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.AI_HOOK,
                command_path=ctx.command_path,
            ),
            secret_config=config.user_config.secret,
        )
        return AIHookScanner(scanner).scan(stdin_content)
    except ValueError as e:
        ui.display_error(str(e.args[0]))
        return 1
    except Exception as e:
        # Any auth / network / unexpected failure must not crash the hook:
        # fail open with a warning surfaced through the agent.
        return emit_fail_open_response(stdin_content, e)
