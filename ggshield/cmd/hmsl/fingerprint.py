from typing import Any, Dict, Iterable, Iterator, Set, TextIO, cast

import click
from dotenv import dotenv_values

from ggshield.cmd.common_options import add_common_options
from ggshield.cmd.hmsl.hmsl_common_options import (
    InputType,
    NamingStrategy,
    full_hashes_option,
    input_arg,
    input_type_option,
    naming_strategy_option,
)
from ggshield.core.text_utils import display_info
from ggshield.hmsl.client import PREFIX_LENGTH
from ggshield.hmsl.collection import PreparedSecrets, SecretWithKey
from ggshield.hmsl.crypto import hash_string
from ggshield.hmsl.utils import EXCLUDED_KEYS, EXCLUDED_VALUES


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
    help="Prefix for output file names.",
    callback=lambda _, __, value: validate_prefix(value),
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
    Collect secrets and prepare them to be queried.
    """
    # Opens the file or stdin
    input = cast(TextIO, click.open_file(path, "r"))

    # Prepare and write the output files
    secrets = list(collect(input, input_type))
    result = prepare(secrets, naming_strategy, full_hashes=full_hashes)
    write_outputs(result, prefix)

    display_info(f"Prepared {len(secrets)} secrets.")
    return 0


# Helper methods


def collect(
    input: TextIO, input_type: InputType = InputType.FILE
) -> Iterator[SecretWithKey]:
    """
    Collect the secrets
    """
    if input_type == InputType.ENV:
        config = dotenv_values(stream=input)
        for key, value in config.items():
            # filter our excluded keys and values
            if not key or not value:
                continue
            if key.upper() in EXCLUDED_KEYS or value.lower() in EXCLUDED_VALUES:
                continue
            yield SecretWithKey(value=value, key=key)
    else:
        for line in input:
            secret = line.strip()
            if secret == "":
                # Skip empty lines
                continue
            yield SecretWithKey(value=secret, key=None)


def prepare(
    secrets: Iterable[SecretWithKey],
    naming_strategy: NamingStrategy,
    *,
    full_hashes: bool = False,
) -> PreparedSecrets:
    """
    Prepare the secrets so they can later be checked.
    """
    hashes: Set[str] = set()
    mapping: Dict[str, str] = {}
    for secret in secrets:
        name = naming_strategy(secret)
        hash = hash_string(secret.value)
        mapping[hash] = name
        if full_hashes:
            hashes.add(hash)
        else:
            hashes.add(hash[:PREFIX_LENGTH])
    return PreparedSecrets(
        payload=hashes,
        mapping=mapping,
    )


def write_outputs(result: PreparedSecrets, prefix: str) -> None:
    """
    Write payload and mapping files.
    """
    with open(f"{prefix}payload.txt", "w") as payload_file:
        payload_file.write("\n".join(result.payload) + "\n")

    with open(f"{prefix}mapping.txt", "w") as mapping_file:
        for hash, hint in result.mapping.items():
            line = hash + ":" + hint if hint else hash
            mapping_file.write(line + "\n")
    display_info(
        f"{prefix}payload.txt and {prefix}mapping.txt files have been written."
    )
