from typing import Any, TextIO, cast

import click

from ggshield.cmd.hmsl.hmsl_common_options import (
    full_hashes_option,
    input_arg,
    input_type_option,
    naming_strategy_option,
)
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.core import ui
from ggshield.verticals.hmsl.collection import (
    InputType,
    NamingStrategy,
    collect,
    prepare,
)
from ggshield.verticals.hmsl.output import write_outputs


def validate_prefix(prefix: str) -> str:
    if prefix != "" and not prefix.endswith("-"):
        prefix = prefix + "-"
    return prefix


@click.command()
@add_common_options()
@click.option(
    "--prefix",
    "-p",
    default="",
    help="Prefix for output file names. For instance `-p foo` produces `foo-payload.txt` and `foo-mapping.txt`.",
    callback=lambda _, __, value: validate_prefix(value),
    metavar="PREFIX",
)
@full_hashes_option
@naming_strategy_option
@input_type_option
@input_arg
def fingerprint_cmd(
    path: str,
    prefix: str,
    naming_strategy: NamingStrategy,
    full_hashes: bool,
    input_type: InputType,
    **_: Any,
) -> int:
    """
    Collect secrets and compute fingerprints.

    Fingerprints are to be used later by the `decrypt` command.

    Note: Secrets can be read from stdin using `ggshield hmsl fingerprint -`.
    """
    # Opens the file or stdin
    input = cast(TextIO, click.open_file(path, "r"))

    # Prepare and write the output files
    secrets = list(collect(input, input_type))
    result = prepare(secrets, naming_strategy, full_hashes=full_hashes)
    write_outputs(result, prefix)

    ui.display_info(f"Prepared {len(secrets)} secrets.")
    return 0
