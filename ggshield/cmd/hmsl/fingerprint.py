from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterable, Iterator, Optional, Set, TextIO, cast

import click
from dotenv import dotenv_values

from ggshield.cmd.common_options import add_common_options
from ggshield.core.filter import censor_string
from ggshield.core.text_utils import display_info
from ggshield.hmsl.client import PREFIX_LENGTH
from ggshield.hmsl.crypto import hash_string
from ggshield.hmsl.utils import EXCLUDED_KEYS, EXCLUDED_VALUES


# Types and constants
class InputType(Enum):
    FILE = auto()
    ENV = auto()


@dataclass
class PreparedSecrets:
    payload: Set[str]
    mapping: Dict[str, str]


@dataclass
class SecretWithKey:
    key: Optional[str]
    value: str


# Methods to compute names for secrets
# They are useful to help the user identify the secret that may leaked
# with a more "human-readable" string than a hash.
# Takes the secret and optional key as input and returns a string.
NamingStrategy = Callable[[SecretWithKey], str]

NAMING_STRATEGIES: Dict[str, NamingStrategy] = {
    "censored": lambda secret: censor_string(secret.value),
    "cleartext": lambda secret: secret.value,
    "none": lambda _: "",
    "key": lambda secret: secret.key or censor_string(secret.value),
}


# Command

input_arg = click.argument(
    "path",
    type=click.Path(
        exists=True,
        dir_okay=False,
        readable=True,
        allow_dash=True,
    ),
)

naming_strategy_option = click.option(
    "--naming-strategy",
    "-n",
    type=click.Choice(list(NAMING_STRATEGIES.keys())),
    default="key",
    show_default=True,
    help="""Strategy to generate the hints.
            With "censored", only the first and last characters are displayed.
            With "cleartext", the full secret is used as a hint (Not recommended!).
            With "none", no hint is generated.
            With "key", the key name is selected if available (e.g. in .env files), otherwise censored is used.""",
    callback=lambda _, __, value: NAMING_STRATEGIES[value],
)

input_type_option = click.option(
    "--type",
    "-t",
    "input_type",
    type=click.Choice(["file", "env"]),
    default="file",
    show_default=True,
    help="""Type of input to process.
            With "file", the input is a simple file containing secrets.
            With "env", the input is a file containing environment variables.""",
    callback=lambda _, __, value: InputType[value.upper()],
)

full_hashes_option = click.option(
    "-f",
    "--full-hashes",
    is_flag=True,
    default=False,
    help="Send full hashes instead of prefixes.",
)


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
