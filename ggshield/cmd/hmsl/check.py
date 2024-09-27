import logging
from typing import Any, TextIO, cast

import click

from ggshield.cmd.hmsl.hmsl_common_options import (
    full_hashes_option,
    input_arg,
    input_type_option,
    naming_strategy_option,
)
from ggshield.cmd.hmsl.hmsl_utils import check_secrets
from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.core import ui
from ggshield.verticals.hmsl.collection import (
    InputType,
    NamingStrategy,
    collect,
    prepare,
)


logger = logging.getLogger(__name__)


@click.command()
@click.pass_context
@add_common_options()
@text_json_format_option
@json_option
@full_hashes_option
@naming_strategy_option
@input_type_option
@input_arg
def check_cmd(
    ctx: click.Context,
    path: str,
    full_hashes: bool,
    naming_strategy: NamingStrategy,
    input_type: InputType,
    **kwargs: Any,
) -> int:
    """
    Check if secrets have leaked.

    Note: Secrets can be read from stdin using `ggshield hmsl check -`.
    """

    # Collect secrets
    ui.display_info("Collecting secrets...")
    input = cast(TextIO, click.open_file(path, "r"))
    secrets = list(collect(input, input_type))
    # full_hashes is True because we need the hashes to decrypt the secrets.
    # They will correctly be truncated by our client later.
    prepared_data = prepare(secrets, naming_strategy, full_hashes=True)
    ui.display_info(f"Collected {len(prepared_data.payload)} secrets.")

    check_secrets(
        ctx=ctx,
        prepared_secrets=prepared_data,
        full_hashes=full_hashes,
    )

    return 0
