import json
import logging
from dataclasses import asdict
from typing import Any, List, TextIO, Tuple, cast

import click
from requests import HTTPError

from ggshield.cmd.common_options import add_common_options
from ggshield.cmd.hmsl.fingerprint import input_arg
from ggshield.core.config import Config
from ggshield.core.errors import ParseError, UnexpectedError
from ggshield.core.text_utils import display_info, pluralize
from ggshield.hmsl import HASH_REGEX, PREFIX_REGEX, get_client


logger = logging.getLogger(__name__)


@click.command()
@click.pass_context
@add_common_options()
@input_arg
def query_cmd(
    ctx: click.Context,
    path: str,
    **kwargs: Any,
) -> int:
    """
    Query HasMySecretLeaked.
    """

    # Opens the file or stdin
    input = cast(TextIO, click.open_file(path, "r"))
    payload, full_hashes = load_payload(input)

    # Get our client
    config: Config = ctx.obj["config"]
    client = get_client(config)

    # Send the hashes to the API
    try:
        for result in client.query(payload, full_hashes=full_hashes):
            line = json.dumps(asdict(result))
            click.echo(line)
    except (ValueError, HTTPError) as error:
        raise UnexpectedError(str(error))

    display_info(
        f"{client.quota.remaining} {pluralize('credit', client.quota.remaining)} left for today."
    )
    display_info(f"Queried {len(payload)} {pluralize('secret', len(payload))}.")
    return 0


def load_payload(input: TextIO) -> Tuple[List[str], bool]:
    """Load the payload from the input file.
    Return a list of string and a boolean indicating if they are full hashes (True)
    or prefixes (False).
    """
    # Remove empty lines
    data = list({line.strip() for line in input} - {""})
    # Check if we have full hashes or prefixes
    if not (
        all(HASH_REGEX.match(line) for line in data)
        or all(PREFIX_REGEX.match(line) for line in data)
    ):
        raise ParseError(
            "Invalid payload format. Did you forget to prepare your secrets?"
        )
    full_hashes = len(data) > 0 and len(data[0]) == 64
    return data, full_hashes
