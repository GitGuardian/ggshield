from typing import Iterable, Optional

import click
from requests import HTTPError

from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import pluralize
from ggshield.verticals.hmsl import Secret, get_client
from ggshield.verticals.hmsl.collection import PreparedSecrets
from ggshield.verticals.hmsl.output import show_results


def check_secrets(
    ctx: click.Context,
    prepared_secrets: PreparedSecrets,
    full_hashes: bool,
):
    """
    Common code to check secrets and display results for check commands.
    """
    # Query the API
    ui.display_info("Querying HasMySecretLeaked...")
    ctx_obj = ContextObj.get(ctx)
    client = get_client(ctx_obj.config, hmsl_command_path=ctx.command_path)
    found: Iterable[Secret] = []
    error: Optional[Exception] = None
    try:
        found = list(client.check(prepared_secrets.payload, full_hashes=full_hashes))
    except (ValueError, HTTPError) as exception:
        error = exception
    ui.display_info(
        f"{client.quota.remaining} {pluralize('credit', client.quota.remaining)} left for today."
    )

    # Display results and error
    show_results(
        found, prepared_secrets.mapping, json_output=ctx_obj.use_json, error=error
    )
    if error:
        raise UnexpectedError(str(error))
