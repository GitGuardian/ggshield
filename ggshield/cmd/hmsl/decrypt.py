import json
from typing import Any, Dict, Iterable, Iterator, TextIO, cast

import click

from ggshield.cmd.common_options import add_common_options, json_option
from ggshield.cmd.hmsl.fingerprint import input_arg
from ggshield.core.errors import ParseError
from ggshield.core.text_utils import display_heading, display_warning, pluralize
from ggshield.hmsl import Match, Secret
from ggshield.hmsl.crypto import make_hint


# Types and constants
TEMPLATE = """
> Secret {number}
Secret name: "{name}"
Secret hash: "{hash}"
Distinct locations: {count}
First occurrence:
    URL: "{url}"
"""


# Command


@click.command()
@add_common_options()
@click.option(
    "--mapping",
    "-m",
    "mapping_file",
    type=click.File("r"),
    default="mapping.txt",
    show_default=True,
    help="File containing the hashes and their names.",
)
@json_option
@input_arg
def decrypt_cmd(path: str, mapping_file: TextIO, json_output: bool, **_: Any) -> int:
    """
    Decrypt and show secrets information.
    """
    # Opens the file or stdin
    input = cast(TextIO, click.open_file(path, "r"))
    mapping: Dict[str, str] = load_mapping(mapping_file)

    # Decrypt the secrets thanks to the hashes contained in mapping
    try:
        secrets = decrypt(input, mapping)
        # Display the secrets
        show_results(secrets, mapping, json_output)
    except (json.JSONDecodeError, TypeError):
        raise ParseError("Invalid format in input file.")

    return 0


# Helper methods


def load_mapping(mapping_file: TextIO) -> Dict[str, str]:
    """
    Load the mapping from the file.
    """
    mapping: Dict[str, str] = {}
    for line in mapping_file:
        line = line.strip()
        if line == "":
            # Skip empty lines
            continue
        hash, name = line.split(":", maxsplit=1)
        mapping[hash] = name
    return mapping


def decrypt(input: TextIO, mapping: Dict[str, str]) -> Iterator[Secret]:
    """
    Decrypt the secrets thanks to the hashes contained in mapping.
    """
    hashes = set(mapping.keys())
    hints = {make_hint(hash): hash for hash in hashes}
    for line in input:
        line = line.strip()
        if line == "":
            # Skip empty lines
            continue
        data = json.loads(line)
        if data.keys() == {"hint", "payload"}:
            match = Match(**json.loads(line))
            if match.hint in hints:
                yield match.decrypt(hints[match.hint])
        else:
            yield Secret(**data)


def show_results(
    secrets: Iterable[Secret], names: Dict[str, str], json_output: bool
) -> None:
    """
    Display the secrets.
    """
    secrets = list(secrets)
    if secrets:
        display_warning(
            f"Found {len(secrets)} leaked {pluralize('secret', len(secrets))}."
        )
    else:
        display_heading("All right! No leaked secret has been found.")

    data = {
        "leaks_count": len(secrets),
        "leaks": [
            {
                "name": names.get(secret.hash) or secret.hash,
                "hash": secret.hash,
                "count": secret.count,
                "url": secret.url,
            }
            for secret in secrets
        ],
    }
    if json_output:
        click.echo(json.dumps(data))
    else:
        for i, secret in enumerate(data["leaks"]):
            click.echo(TEMPLATE.format(number=i + 1, **secret))
