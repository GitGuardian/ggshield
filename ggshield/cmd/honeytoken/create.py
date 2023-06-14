import random
import string
from pathlib import Path
from typing import Any, Dict, Optional

import click
from pygitguardian import GGClient
from pygitguardian.models import Detail, HoneytokenResponse

from ggshield.cmd.common_options import add_common_options
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError


def _generate_random_honeytoken_name() -> str:
    """Generate a honeytoken name based on a random string of eight alphanumeric characters"""
    letters_and_digits = string.ascii_letters + string.digits
    random_str = "".join(random.choice(letters_and_digits) for i in range(8))
    return f"ggshield-{random_str}"


def _dict_to_string(data: Dict, space: bool = False) -> str:
    """Returns a string with 'key=value' for each key-value pair in the dictionary."""
    space_char = " " if space else ""
    return "\n".join([f"{k}{space_char}={space_char}{v}" for k, v in data.items()])


@click.command()
@click.option(
    "--name",
    "name",
    required=False,
    type=str,
    help="Specify a name for your honeytoken. If this option is not provided, a unique name will be generated with a \
'ggshield-' prefix.",
)
@click.option(
    "--type",
    "type_",
    required=True,
    type=click.Choice(("AWS",)),
    help="Specify the type of honeytoken that you want to create. (For now only AWS honeytokens are supported!)",
)
@click.option(
    "--description",
    "description",
    required=False,
    type=str,
    help="Add a description to your honeytoken (250 characters max).",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(
        path_type=Path, file_okay=True, dir_okay=False, readable=True, writable=True
    ),
    required=False,
    help="Specify a filename to append your honeytoken directly to the content of this file. \
If the file does not exist, it will be created.",
)
@add_common_options()
@click.pass_context
def create_cmd(
    ctx: click.Context,
    name: Optional[str],
    type_: str,
    description: Optional[str],
    output_file: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Command to create a honeytoken.
    This action is restricted to authorized users only. To learn more, visit
    <https://docs.gitguardian.com/honeytoken/getting-started>
    """
    # if name is not given, generate a random one
    if not name:
        name = _generate_random_honeytoken_name()
    client: GGClient = create_client_from_config(ctx.obj["config"])
    response = client.create_honeytoken(name, type_, description)
    if not isinstance(response, (Detail, HoneytokenResponse)):
        raise UnexpectedError("Unexpected honeytoken response")

    if isinstance(response, Detail) and response.status_code == 403:
        raise UnexpectedError(
            """ggshield does not have permissions to create honeytokens on your workspace. Make sure that:

- the honeytoken module is enabled for your GitGuardian workspace,
- you have the necessary permissions as a user,
- the personal access token used by ggshield has the required scopes (honeytoken:write).

To learn more, visit https://docs.gitguardian.com/honeytoken/getting-started."""
        )
    elif isinstance(response, Detail):
        raise UnexpectedError(response.detail)
    honeytoken: HoneytokenResponse = response

    token_to_display = {
        f"{honeytoken.type_}_{k}".lower(): v for k, v in honeytoken.token.items()
    }

    if output_file:
        click.echo(
            f"Your honeytoken has been created successfully in {output_file}\n"
            f'Your honeytoken #{honeytoken.id} "{honeytoken.name}" is accessible in your workspace: '
            f"{honeytoken.gitguardian_url}\n"
        )

        # special output for piped or redirect
        with open(output_file, "a") as opened_output_file:
            opened_output_file.write(f"{_dict_to_string(token_to_display)}\n")

    else:
        click.echo(
            "Your honeytoken has been created successfully.\n"
            "You can now paste it into your code. We recommend that you place it in one unique place.\n"
            "-------------------------------\n"
            f"{_dict_to_string(token_to_display, space=True)}\n"
            "-------------------------------\n"
            f'Your honeytoken #{honeytoken.id} "{honeytoken.name}" is accessible in your workspace: '
            f"{honeytoken.gitguardian_url}\n"
        )

    return 0
