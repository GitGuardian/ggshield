from collections import Counter
from pathlib import Path
from typing import Any, List, Optional

import click
from pygitguardian.models import Detail, HoneytokenWithContextResponse

from ggshield.cmd.honeytoken.utils import generate_random_honeytoken_name
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.utils.click import RealPath


def _list_extensions_in_dir(dir: Path, max_depth: int = 3, depth: int = 0) -> List[str]:
    ext_list = []
    for path in dir.glob("*"):
        if path.is_file() and path.suffix:
            ext_list.append(path.suffix)
        if path.is_dir() and depth < max_depth:
            ext_list.extend(_list_extensions_in_dir(path, max_depth, depth + 1))
    return ext_list


def _get_most_common_extensions_in_dir(dir: Path):
    """
    Return the most 3 common extensions in a directory
    """
    counter = Counter(_list_extensions_in_dir(dir))
    return [extension for extension, _ in counter.most_common(3)]


@click.command()
@click.option(
    "--name",
    "name",
    required=False,
    type=str,
    help="Specify a name for your honeytoken. If this option is not provided, a unique name will be generated with a \
`ggshield-` prefix.",
)
@click.option(
    "--type",
    "type_",
    required=True,
    type=click.Choice(("AWS",)),
    help="Specify the type of honeytoken that you want to create. (For now only AWS honeytokens are supported)",
)
@click.option(
    "--description",
    "description",
    required=False,
    type=str,
    help="Add a description to your honeytoken (250 characters max).",
)
@click.option(
    "--language",
    "language",
    required=False,
    type=str,
    help="Language to use for the context. If not set, ggshield infers the language \
        from the repository or from OUTPUT_FILE, if set.",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    type=RealPath(file_okay=True, dir_okay=False, readable=True, writable=True),
    required=False,
    help="Filename to store your honeytoken.",
)
@add_common_options()
@click.pass_context
def create_with_context_cmd(
    ctx: click.Context,
    name: Optional[str],
    type_: str,
    description: Optional[str],
    output_file: Optional[Path],
    language: Optional[str],
    **kwargs: Any,
) -> int:
    """
    Create a honeytoken within a context.

    The context is a realistic file in which your honeytoken is inserted.
    Adding your honeytoken within a relevant context makes it look more credible.

    The prerequisites to use this command are the following:

    - you have the necessary permissions as a user (for now, Honeytoken is
    restricted to users with a "Manager" access level),

    - the personal access token used by ggshield has the `honeytokens:write`
    scope.
    """
    # if name is not given, generate a random one
    if not name:
        name = generate_random_honeytoken_name()
    ctx_obj = ContextObj.get(ctx)
    client = create_client_from_config(ctx_obj.config)

    response = client.create_honeytoken_with_context(
        name=name,
        type_=type_,
        description=description,
        language=language,
        filename=output_file.name if output_file else None,
        project_extensions=(
            []
            if language or output_file
            else _get_most_common_extensions_in_dir(Path("."))
        ),
    )

    if not isinstance(response, (Detail, HoneytokenWithContextResponse)):
        raise UnexpectedError("Unexpected honeytoken response")

    if (
        isinstance(response, Detail)
        and response.status_code == 403
        and "allowlist" not in response.detail
    ):
        raise UnexpectedError(
            """ggshield does not have permissions to create honeytokens on your workspace. Make sure that:

- the honeytoken module is enabled for your GitGuardian workspace,
- you have the necessary permissions as a user,
- the personal access token used by ggshield has the `honeytokens:write` scope.

To learn more, visit https://docs.gitguardian.com/honeytoken/getting-started."""
        )
    elif isinstance(response, Detail):
        raise UnexpectedError(response.detail)

    filepath_to_write = Path(response.filename)

    click.echo(
        "Honeytoken created and placed in the following context:\n"
        f"- file: {filepath_to_write.absolute()}\n"
        f"- language: {response.language}\n"
        "\n"
        f'Your honeytoken "{name}" is accessible in your workspace: {response.gitguardian_url}'
    )

    filepath_to_write.write_text(response.content)

    return 0
