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
    help="""Strategy to generate the hints in the output.

            \b
            - `censored`: only the first and last characters are displayed.
            - `cleartext`: the full secret is used as a hint (Not recommended!).
            - `none`: no hint is generated.
            - `key`: the key name is selected if available (e.g. in .env files), otherwise censored is used.""",
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

            \b
            - `file`: the input is a simple file containing secrets.
            - `env`: the input is a file containing environment variables.""",
    callback=lambda _, __, value: InputType[value.upper()],
)
full_hashes_option = click.option(
    "-f",
    "--full-hashes",
    is_flag=True,
    default=False,
    help=(
        "Put the full hashes into the payload instead of the prefixes. This is useful"
        " for partners that trust GitGuardian because it allows to send more hashes"
        " per batch, and consumes less credits."
    ),
)
