import click

from ggshield.verticals.hmsl.collection import NAMING_STRATEGIES, InputType


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
