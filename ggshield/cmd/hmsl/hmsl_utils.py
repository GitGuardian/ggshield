from typing import Iterable, Optional

import click
from requests import HTTPError

from ggshield.core.config import Config
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import display_info, pluralize
from ggshield.verticals.hmsl import Secret, get_client
from ggshield.verticals.hmsl.collection import PreparedSecrets
from ggshield.verticals.hmsl.output import show_results


def check_secrets(
    ctx: click.Context,
    prepared_secrets: PreparedSecrets,
    json_output: bool,
    full_hashes: bool,
):
    """
    Common code to check secrets and display results for check commands.
    """
    # Query the API
    display_info("Querying HasMySecretLeaked...")
    config: Config = ctx.obj["config"]
    client = get_client(config)
    found: Iterable[Secret] = []
    error: Optional[Exception] = None
    try:
        found = list(client.check(prepared_secrets.payload, full_hashes=full_hashes))
    except (ValueError, HTTPError) as exception:
        error = exception
    display_info(
        f"{client.quota.remaining} {pluralize('credit', client.quota.remaining)} left for today."
    )

    # Display results and error
    show_results(found, prepared_secrets.mapping, json_output, error)
    if error:
        raise UnexpectedError(str(error))
