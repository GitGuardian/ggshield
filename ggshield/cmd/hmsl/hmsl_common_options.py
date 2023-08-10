from enum import Enum, auto
from typing import Callable, Dict

import click

from ggshield.core.filter import censor_string
from ggshield.hmsl.collection import SecretWithKey


class InputType(Enum):
    FILE = auto()
    ENV = auto()


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
